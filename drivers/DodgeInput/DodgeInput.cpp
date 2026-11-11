// SPDX-License-Identifier: BSD-2-Clause-Patent
#include "OriginalHidDeviceABI.h"
#include "Mapping.h"
#include "Buttons.h"
#include <PaganiPeripherals.h>
#include <IOKit/IOBufferMemoryDescriptor.h>
#include <IOKit/IOWorkLoop.h>
#include <IOKit/IOTimerEventSource.h>
#include <libkern/c++/OSString.h>
#include <kern/clock.h>
#include <pexpert/pexpert.h>
#include <SmmuTakeover.h>
#include <Rpmh.h>
extern "C" {
#include "S3910.h"
#include <GeniSpi.h>
}

#include "Reports.h"
#include "DodgeHidEvents.h"
#include "DodgeTouchPower.h"
#include "DodgePmicGpio.h"
#include "DodgeGeniFirmware.h"
#include "DodgeTouchClock.h"
#include "DodgeGeniTransfer.h"
#include "DodgeInputStatus.h"
#include "DodgeInputLifecycle.h"
extern "C" const uint8_t dodge_touch_spi_firmware[],dodge_touch_spi_firmware_end[];

static void dmaCache(void *bytes,size_t size,unsigned operation) {
    uint64_t ctr;__asm__ volatile("mrs %0, ctr_el0" : "=r"(ctr));
    uintptr_t line=4ULL<<((ctr>>16)&15),end=(uintptr_t)bytes+size;
    for (uintptr_t at=(uintptr_t)bytes&~(line-1);at<end;at+=line) {
        if (operation==0) __asm__ volatile("dc cvac, %0" :: "r"(at) : "memory");
        else if (operation==1) __asm__ volatile("dc civac, %0" :: "r"(at) : "memory");
        else __asm__ volatile("dc ivac, %0" :: "r"(at) : "memory");
    }
    __asm__ volatile("dsb sy" ::: "memory");
}
static void dmaClean(void *,void *p,size_t n) {dmaCache(p,n,0);}
static void dmaCleanInval(void *,void *p,size_t n) {dmaCache(p,n,1);}
static void dmaInval(void *,void *p,size_t n) {dmaCache(p,n,2);}

class DodgeInput : public IOHIDDevice {
    OSDeclareDefaultStructors(DodgeInput)
    IOWorkLoop *loop=nullptr;
    IOTimerEventSource *timer=nullptr;
    IOService *touchEvents=nullptr;
    bool touch=false,running=false,timerAdded=false;
    bool starting=false,parentCleanupPending=false,tickActive=false,stopRequested=false,parentStopping=false;
    IOService *pendingStopProvider=nullptr;
    PeripheralWindow core,cnfg,obs,channels,gcc,se,wrapper,smmu,rsc,cmddb,pins[6];
    IOBufferMemoryDescriptor *dmaMemory=nullptr;
    bool dmaExposed=false,firstReadCaptured=false,hardwareTouched=false;
    geni_spi spi={};
    s3910 controller={};
    s3910_frame previous={};
    pagani_button_filter filter={};
    int pon=-1,gpio=-1;
    uint8_t lastButtons=0;
    uint32_t savedPins[6]={};
    uint32_t savedReset=0;
    unsigned pinsConfigured=0;
    const char *phase="allocate";
    uint32_t sample=0;
    uint32_t touchBinding=0,touchUsage=0xffffffff,lastInputXY=0;
    uint64_t reports=0;
    int touchError=0;
    char touchPhase[24]={};
    void observe(const char *stage,int result=0) {
        phase=stage;
        dodge_input_observe(touch?DODGE_TOUCH:DODGE_KEYS,phase,result,sample,reports);
    }
    void observeTouch(int result) {
        snprintf(touchPhase,sizeof touchPhase,"T%u %02x %s",controller.version,controller.command,controller.stage);
        sample=controller.detail;observe(touchPhase,result);
    }
    int transferTouch(const uint8_t *tx,uint8_t *rx,size_t size) {
        if (touchError) return touchError;
        spi.snap_valid=0;
        bool capture=rx && !firstReadCaptured;
        uint32_t pin=capture?(PeripheralWindow::read(&pins[5],4)&1):0;
        if (spi.use_dma) dmaExposed=true;
        int rc=dodge_geni_transfer(&spi,tx,rx,size,&touchError);
        if (rc) controller.ready=0;
        // Preserve the driver's pre-cancel snapshot; live registers now describe recovery.
        if (rc && spi.snap_valid) dodge_input_touch_spi(spi.info.fw_revision,spi.info.if_disable,
            spi.snap_status,spi.snap_irq,spi.snap_txfs,spi.snap_rxfs);
        if (rc && spi.snap_valid && spi.use_dma) dodge_input_touch_dma(
            spi.snap_dma_tx,spi.snap_dma_rx,spi.snap_dma_txin,spi.snap_dma_rxin);
        if (!rc && capture) {
            uint32_t head=0;
            for (size_t i=0;i<size && i<4;++i) head|=(uint32_t)rx[i]<<(8*i);
            pin|=(PeripheralWindow::read(&pins[5],4)&1)<<1;
            pin|=(PeripheralWindow::read(&pins[4],4)&3)<<2;
            dodge_input_touch_read((uint32_t)size,head,pin,(uint32_t)spi.use_dma,
                spi.se.rd(spi.se.ctx,SE_GENI_STATUS),spi.last_tx_in,spi.last_rx_in,
                spi.se.rd(spi.se.ctx,SM8750_SPI_DELAY_COUNTERS));
            firstReadCaptured=true;
        }
        return rc;
    }
    static int readTouch(void *ctx,uint8_t *data,size_t size) {
        uint8_t dummy[S3910_PAYLOAD_MAX+7];
        if (!data || !size) return -22;
        if (size>sizeof dummy) return -90;
        // Synaptics reads clock 0xff on MOSI, as in the stock HBP SPI transport.
        memset(dummy,0xff,size);
        return static_cast<DodgeInput *>(ctx)->transferTouch(dummy,data,size);
    }
    static int writeTouch(void *ctx,const uint8_t *data,size_t size) {
        return static_cast<DodgeInput *>(ctx)->transferTouch(data,nullptr,size);
    }
    static void sleepTouch(void *,unsigned ms) {IOSleep(ms);}
    int setupDma() {
        constexpr size_t bytes=4096;
        static_assert(S3910_PAYLOAD_MAX+7<=bytes,"touch transfer fits DMA page");
        static_assert(S3910_PAYLOAD_MAX+7<=DODGE_GENI_TRANSFER_MAX,"touch transfer fits terminal guard");
        observe("DMA allocate");
        dmaMemory=IOBufferMemoryDescriptor::inTaskWithOptions(kernel_task,
            static_cast<IOOptionBits>(kIODirectionInOut)|static_cast<IOOptionBits>(kIOMemoryPhysicallyContiguous)|
            static_cast<IOOptionBits>(kIOMemoryMapperNone),2*bytes,bytes);
        if (!dmaMemory) return -12;
        IOByteCount contiguous=0;
        uint64_t physical=dmaMemory->getPhysicalSegment(0,&contiguous,kIOMemoryMapperNone);
        auto virt=static_cast<uint8_t *>(dmaMemory->getBytesNoCopy());
        if (!virt || !physical || (physical&(bytes-1)) || contiguous<2*bytes) return -14;
        memset(virt,0,2*bytes);dmaCache(virt,2*bytes,1);
        observe("SMMU map");
        if (!smmu.map(PAGANI_TOUCH_SMMU,PAGANI_TOUCH_SMMU_SIZE)) return -12;
        auto read=[this](unsigned at) {return PeripheralWindow::read(&smmu,at);};
        auto write=[this](unsigned at,uint32_t value) {PeripheralWindow::write(&smmu,at,value);};
        // Refuse an existing translated/shared QUP stream; do not alter firmware bank 0.
        auto plan=planUfsSmmu(PAGANI_TOUCH_SMMU_SID,physical,2*bytes,read,PAGANI_TOUCH_SMMU_SIZE);
        sample=(plan.slot<<16)|plan.bank;observe(plan.error?"SMMU conflict":"SMMU configure");
        const char *error=configureUfsSmmu(plan,PAGANI_TOUCH_SMMU_SID,read,write);
        if (error) {
            IOLog("Dodge touch SMMU: %s slot=%u smr=%x s2cr=%x\n",error,plan.slot,plan.smr,plan.s2cr);
            dodge_input_touch_smmu(plan.slot,plan.bank,plan.smr,plan.s2cr);return -16;
        }
        observe("SMMU sync");unsigned polls=0;
        if (!syncUfsSmmu(read,write,[&] {IODelay(10);return ++polls>=10000;},sample)) return -110;
        spi.use_dma=1;
        spi.dma={nullptr,dmaClean,dmaCleanInval,dmaInval,virt,virt+bytes,physical,physical+bytes,bytes};
        return 0;
    }
    int setupButtons() {
        observe("SPMI map");
        if (!core.map(PAGANI_SPMI_CORE,0x3000) || !cnfg.map(PAGANI_SPMI_CNFG,0x4000) || !obs.map(PAGANI_SPMI_OBS,0x80000)) return -12;
        auto c=core.io(),f=cnfg.io();
        observe("SPMI channels");
        pon=spmi_find(&c,&f,PAGANI_PON_PPID,PAGANI_SPMI_EE);
        gpio=spmi_find(&c,&f,PAGANI_GPIO_PPID,PAGANI_SPMI_EE);
        sample=((uint32_t)pon<<16)|((uint32_t)gpio&0xffff);
        if (pon<0 || gpio<0) return -19;
        auto o=obs.io();uint8_t subtype=0,type=0,mode=0,enable=0;
        observe("PON subtype");
        int rc=spmi_read8(&o,PAGANI_SPMI_EE,pon,5,&subtype);sample=subtype;
        if (rc || subtype!=9) return rc?rc:-19;
        observe("GPIO type");rc=spmi_read8(&o,PAGANI_SPMI_EE,gpio,4,&type);sample=type;
        if (rc || type!=0x10) return rc?rc:-19;
        observe("GPIO subtype");rc=spmi_read8(&o,PAGANI_SPMI_EE,gpio,5,&subtype);sample=subtype;
        if (rc || subtype<0x10 || subtype>0x13) return rc?rc:-19;
        observe("GPIO mode");rc=spmi_read8(&o,PAGANI_SPMI_EE,gpio,0x40,&mode);sample=mode;
        if (rc || (mode&3)) return rc?rc:-19;
        observe("GPIO enable");rc=spmi_read8(&o,PAGANI_SPMI_EE,gpio,0x46,&enable);sample=enable;
        if (rc || !(enable&0x80)) return rc?rc:-19;
        return 0;
    }
    int setupTouchPower() {
        observe("power map");
        if (!rsc.map(PAGANI_TOUCH_RSC,PAGANI_TOUCH_RSC_SIZE) ||
            !cmddb.map(PAGANI_CMD_DB,PAGANI_CMD_DB_SIZE,kIOMapReadOnly) ||
            !core.map(PAGANI_SPMI_CORE,0x3000) || !cnfg.map(PAGANI_SPMI_CNFG,0x4000) ||
            !obs.map(PAGANI_SPMI_OBS,0x80000) || !channels.map(PAGANI_SPMI_CHANNELS,PAGANI_SPMI_CHANNEL_BYTES)) return -12;
        auto db=cmddb.io(),power=rsc.io(),c=core.io(),f=cnfg.io(),o=obs.io(),w=channels.io();
        return dodge_touch_power_sequence([&] {
            uint32_t address=0;observe("power VDD lookup");
            int rc=rpmh_vrm_address(&db,PAGANI_CMD_DB_SIZE,PAGANI_TOUCH_VDD,&address);if (rc) return rc;
            if (address!=PAGANI_TOUCH_VDD_VRM) return -71;
            sample=address;observe("power VDD");rpmh_result result={};
            rc=sm8750_rpmh_vrm_enable(&power,address,PAGANI_TOUCH_VDD_MV,&result);
            dodge_input_touch_power(address,result.hardware,result.tcs,result.status,
                result.command[0],result.command[1],result.command[2]);return rc;
        },[&] {
            sample=PAGANI_AVDD_PPID;observe("power GPIO AVDD");DodgeGpioInitResult result={};
            int rc=dodge_avdd_initialize(&c,&f,&o,&w,PAGANI_SPMI_CHANNEL_BYTES,
                PAGANI_AVDD_PPID,PAGANI_SPMI_EE,PAGANI_AVDD_ON,&result);
            dodge_input_touch_power(PAGANI_AVDD_PPID,(uint32_t)result.before.apid,result.before.subtype,result.before.mode,
                result.source,result.mode,result.enable);return rc;
        },[](unsigned ms) {IOSleep(ms);},PAGANI_TOUCH_POWER_MS);
    }
    int setupTouch() {
        observe("GCC map");
        if (!gcc.map(PAGANI_GCC_BASE,0x60000)) return -12;
        observe("SPI map");
        if (!se.map(PAGANI_TOUCH_SE,0x4000) || !wrapper.map(PAGANI_TOUCH_WRAPPER,0x1000)) return -12;
        auto g=gcc.io(),clockSe=se.io();DodgeTouchClockResult clock={};
        observe("SPI clock");
        int rc=dodge_touch_clock_prepare(&g,&clockSe,&clock);
        sample=clock.hz;observe(clock.programmed?"SPI XO initialized":"SPI clock checked",rc);
        if (rc) return rc;
        unsigned hz=clock.hz,select=clock.select;
        spi.se={&se,PeripheralWindow::read,PeripheralWindow::write,PeripheralWindow::delay};
        spi.wrapper={&wrapper,PeripheralWindow::read,PeripheralWindow::write,PeripheralWindow::delay};
        // Preserve an existing SPI image. Program the pinned stock image only
        // into an empty idle matching engine, with no GPI/DMA owner.
        observe("GENI firmware");DodgeGeniResult firmware={};
        size_t firmwareBytes=(uintptr_t)dodge_touch_spi_firmware_end-(uintptr_t)dodge_touch_spi_firmware;
        rc=dodge_geni_prepare(&spi,dodge_touch_spi_firmware,firmwareBytes,&firmware);
        sample=(firmware.phase<<24)|(firmware.writes&0xffffffu);
        observe(rc?"GENI load failed":firmware.loaded?"GENI loaded":"GENI adopted",rc);
        if (rc) return rc;
        spi.poll_only=1;spi.poll_limit=20000;
        if (spi.info.fifo_disabled) {
            rc=setupDma();if (rc) return rc;
            // ArmCpu masks unused SPIs at distributor init; retain SE status generation for polling.
            spi.poll_only=2;
        }
        observe("SPI init");rc=geni_spi_init(&spi);if (rc) return rc;
        observe("SPI mode");rc=geni_spi_setup(&spi,0,0);if (rc) return rc;
        observe("SPI rate");rc=geni_spi_set_clock(&spi,PAGANI_TOUCH_HZ,hz,select);if (rc) return rc;
        auto serial=se.io();observe("SPI timing");
        rc=sm8750_spi_timing(&serial,PAGANI_TOUCH_CS_DELAY,PAGANI_TOUCH_WORD_DELAY,&sample);if (rc) return rc;
        rc=setupTouchPower();if (rc) return rc;
        const unsigned gpios[]=PAGANI_TOUCH_PINS;
        const unsigned drives[]=PAGANI_TOUCH_DRIVES;
        for (unsigned i=0;i<6;++i) {
            sample=gpios[i];observe("touch GPIO");
            if (!pins[i].map(PAGANI_TLMM_GPIO(gpios[i]),0x1000)) return -12;
            savedPins[i]=PeripheralWindow::read(&pins[i],0);
            uint32_t cfg=(savedPins[i]&~0x3ffu)|(drives[i]<<6)|(i<4?4:0);
            if (i==4) {
                savedReset=PeripheralWindow::read(&pins[i],4)&2;
                PeripheralWindow::write(&pins[i],4,2); // Set RESET high before enabling output.
                cfg|=1u<<9;
            }
            PeripheralWindow::write(&pins[i],0,cfg);++pinsConfigured;
        }
        PeripheralWindow::write(&pins[4],4,0);IOSleep(PAGANI_TOUCH_RESET_MS);
        PeripheralWindow::write(&pins[4],4,2);IOSleep(PAGANI_TOUCH_STARTUP_MS);
        controller.bus={this,readTouch,writeTouch,sleepTouch};
        observe("TouchComm start");rc=s3910_start(&controller);
        observeTouch(rc);
        return rc;
    }
    IOReturn bindTouchEvents() {
        if (touchEvents) return touchEvents->isInactive()?kIOReturnNotReady:kIOReturnSuccess;
        IOService *driver=dodge_hid::findDriver(this,4);
        if (!driver) return kIOReturnNotReady;
        touchBinding=1;
        touchUsage=(dodge_hid::number(driver,"PrimaryUsagePage")<<16)|dodge_hid::number(driver,"PrimaryUsage");
        if (touchUsage==0xd0004) touchBinding|=4;
        auto *digitizer=OSDynamicCast(OSDictionary,driver->getProperty("Digitizer"));
        if (driver->getProperty("Built-In")==kOSBooleanTrue && driver->getProperty("DisplayIntegrated")==kOSBooleanTrue &&
            digitizer && digitizer->getObject("collectionDispatch")==kOSBooleanTrue) touchBinding|=8;
        if (touchBinding!=13) {driver->release();return kIOReturnUnsupported;}
        // The source event subclass annotates origins through qualified APIs.
        // Original event-driver and event-object vtables stay unchanged.
        touchEvents=driver;return kIOReturnSuccess;
    }
    void showTouchEvents() {
        dodge_input_touch_hid(touchBinding,touchUsage,0,0,0,lastInputXY,0,0);
    }
    bool send(const void *bytes,size_t size) {
        if (!bytes || !size) return false;
        if (touch) {
            IOReturn rc=bindTouchEvents();
            if (rc) {observe(rc==kIOReturnNotReady?"HID wait":"HID bind",rc);return false;}
        }
        auto buffer=IOBufferMemoryDescriptor::withBytes(bytes,size,kIODirectionNone);
        IOReturn rc=buffer?handleReport(buffer,kIOHIDReportTypeInput,0):kIOReturnNoMemory;
        if (!rc) ++reports;
        observe("HID report",rc);
        OSSafeReleaseNULL(buffer);return rc==kIOReturnSuccess;
    }
    void releaseContacts() {
        bool active=false;for (auto &c:previous.contact) active|=c.active!=0;
        if (!active) return;
        s3910_frame empty={};uint8_t report[62];s3910_hid_report(&empty,&previous,report);
        if (send(report,sizeof report)) previous=empty;
    }
    void stopOnGate(IOService *provider) {
        if (starting || tickActive || parentStopping) return;
        if (parentCleanupPending) {
            parentCleanupPending=false;parentStopping=true;
            if (touch) releaseContacts();else {uint8_t report[]={2,0};send(report,2);}
            IOHIDDevice::stop(provider);
            parentStopping=false;
        }
        cleanup();
    }
    void finishPendingStop() {
        if (starting || tickActive || parentStopping || !pendingStopProvider) return;
        auto *provider=pendingStopProvider;pendingStopProvider=nullptr;
        stopOnGate(provider);provider->release();
    }
    static IOReturn stopAction(OSObject *owner,void *argument,void *,void *,void *) {
        auto *self=static_cast<DodgeInput *>(owner);
        auto *provider=static_cast<IOService *>(argument);
        if (!provider || !self->loop || !self->loop->inGate()) return kIOReturnBadArgument;
        self->stopRequested=true;
        __atomic_store_n(&self->running,false,__ATOMIC_RELEASE);
        if (self->timer) {
            self->timer->cancelTimeout();
            if (self->timerAdded) {self->loop->removeEventSource(self->timer);self->timerAdded=false;}
        }
        if (self->starting || self->tickActive) {
            if (!self->pendingStopProvider) {provider->retain();self->pendingStopProvider=provider;}
        } else self->stopOnGate(provider);
        return kIOReturnSuccess;
    }
    static void tick(OSObject *owner,IOTimerEventSource *) {
        auto self=static_cast<DodgeInput *>(owner);
        if (!__atomic_load_n(&self->running,__ATOMIC_ACQUIRE) || self->stopRequested || self->tickActive) return;
        self->tickActive=true;
        if (self->touch) {
            if (self->controller.ready) self->sample=PeripheralWindow::read(&self->pins[5],4)&1;
            if (self->controller.ready && !self->sample) {
                s3910_frame frame={};int rc=s3910_poll(&self->controller,&frame);
                if (rc==1) {
                    self->sample=0;for (unsigned i=0;i<S3910_CONTACTS;++i) if (frame.contact[i].active) self->sample|=1u<<i;
                    for (auto &c:frame.contact) if (c.active) {self->lastInputXY=(uint32_t)c.x<<16|c.y;break;}
                    uint8_t report[62];s3910_hid_report(&frame,&self->previous,report);
                    if (self->send(report,sizeof report)) self->previous=frame;
                    self->showTouchEvents();
                } else if (rc<0) {
                    self->controller.ready=0;self->touchError=rc;self->setProperty("InputError",(uint32_t)rc,32);
                } else {
                    self->sample=self->controller.code;self->observe("TouchComm idle");
                }
            }
            else if (self->controller.ready && !self->reports) self->observe("ATTN wait");
            if (!self->controller.ready) {self->releaseContacts();self->observeTouch(self->touchError);}
        } else {
            uint8_t p=0,g=1;auto io=self->obs.io();
            int rc=spmi_read8(&io,PAGANI_SPMI_EE,self->pon,0x10,&p);
            if (!rc) rc=spmi_read8(&io,PAGANI_SPMI_EE,self->gpio,0x10,&g);
            uint64_t ns=0;absolutetime_to_nanoseconds(mach_absolute_time(),&ns);
            uint8_t mask=pagani_buttons_filter(&self->filter,!rc,pagani_buttons(p,g),ns/1000000);
            self->sample=((uint32_t)p<<8)|g;
            if (mask!=self->lastButtons) {uint8_t report[]={2,mask};if (self->send(report,2)) self->lastButtons=mask;}
            else self->observe("PMIC sample",rc);
        }
        // shortcut: poll the ATTN line and PMIC levels until GIC detach/lifetime support is available.
        self->tickActive=false;
        if (self->stopRequested) self->finishPendingStop();
        else if (__atomic_load_n(&self->running,__ATOMIC_ACQUIRE)) self->timer->setTimeoutMS(self->touch?8:16);
    }
    void cleanup() {
        __atomic_store_n(&running,false,__ATOMIC_RELEASE);
        if (timer) {timer->cancelTimeout();if (timerAdded) loop->removeEventSource(timer);}
        timerAdded=false;
        if (!hardwareTouched) {OSSafeReleaseNULL(timer);OSSafeReleaseNULL(loop);}
        // Once hardware may have been touched, the lifecycle coordinator pins
        // this object/provider and every mapping until reboot. Do not restore
        // pins, release DMA mappings, or reset a live engine on failure/stop.
        if (hardwareTouched) return;
        OSSafeReleaseNULL(touchEvents);
        for (unsigned i=0;i<pinsConfigured;++i) {
            if (i==4) PeripheralWindow::write(&pins[i],4,savedReset);
            PeripheralWindow::write(&pins[i],0,savedPins[i]);
        }
        pinsConfigured=0;for (auto &pin:pins) pin.release();
        if (se.base && spi.use_dma) PeripheralWindow::write(&se,SE_IRQ_EN,0);
        // shortcut: retain the exposed 8 KiB until reboot; DMA reset completion is not yet qualified on this board.
        if (dmaExposed) dmaMemory=nullptr;
        OSSafeReleaseNULL(dmaMemory);
        core.release();cnfg.release();obs.release();channels.release();se.release();wrapper.release();gcc.release();smmu.release();
        // Leave shared rail votes enabled; cleanup must not cut power to another consumer.
        rsc.release();cmddb.release();
    }
public:
    void selectTouch() {touch=true;}
    IOWorkLoop *getWorkLoop() const override {return loop;}
    OSString *newTransportString() const override {return OSString::withCString(touch?"SPI":"SPMI");}
    OSString *newProductString() const override {return OSString::withCString(touch?"Dodge S3910":"Dodge buttons");}
    IOReturn newReportDescriptor(IOMemoryDescriptor **out) const override {
        if (!out) return kIOReturnBadArgument;
        *out=IOBufferMemoryDescriptor::withBytes(touch?touchDescriptor:buttonsDescriptor,
            touch?sizeof touchDescriptor:sizeof buttonsDescriptor,kIODirectionNone);
        return *out?kIOReturnSuccess:kIOReturnNoMemory;
    }
    bool initializeOnGate(IOService *provider) {
        setProperty("HIDDefaultBehavior",true);setProperty("Built-In",true);
        if (touch) {
            setProperty("DisplayIntegrated",true);setProperty("DigitizerCollectionDispatch",true);
            PE_Video video={};
            if (PE_current_console(&video) || video.v_rotate || video.v_width<=2*PAGANI_TOUCH_EDGE_PIXELS ||
                video.v_height<=2*PAGANI_TOUCH_EDGE_PIXELS || !dodge_hid::installPersonality()) {
                observe("HID identity",kIOReturnUnsupported);cleanup();return false;
            }
        }
        hardwareTouched=true;
        int rc=touch?setupTouch():setupButtons();
        if (rc) {observe(phase,rc);IOLog("Dodge %s %s failed: %d\n",touch?"touch":"buttons",phase,rc);cleanup();return false;}
        if (stopRequested) return false;
        observe("HID start");
        // The original start calls this virtual stop on partial failure.
        // Latch its cleanup obligation before entering it, so a deferred stop
        // still cleans the parent exactly once after start has returned.
        parentCleanupPending=true;
        if (!IOHIDDevice::start(provider)) {observe(phase,kIOReturnError);return false;}
        if (stopRequested) return false;
        timer=IOTimerEventSource::timerEventSource(this,tick);
        timerAdded=timer && loop->addEventSource(timer)==kIOReturnSuccess;
        if (!timerAdded) {observe("timer",kIOReturnNoResources);return false;}
        observe("ready");
        __atomic_store_n(&running,true,__ATOMIC_RELEASE);timer->setTimeoutMS(1);return true;
    }
    static IOReturn startAction(OSObject *owner,void *argument,void *,void *,void *) {
        auto *self=static_cast<DodgeInput *>(owner);
        if (!self->loop || !self->loop->inGate() || self->starting || self->parentCleanupPending || self->stopRequested)
            return kIOReturnNotReady;
        self->starting=true;
        bool ok=self->initializeOnGate(static_cast<IOService *>(argument));
        self->starting=false;
        if (!ok || self->stopRequested) {self->stopOnGate(static_cast<IOService *>(argument));ok=false;}
        self->finishPendingStop();
        return ok?kIOReturnSuccess:kIOReturnNotReady;
    }
    bool start(IOService *provider) override {
        if (!provider || loop || stopRequested) return false;
        observe("work loop");
        loop=IOWorkLoop::workLoop();if (!loop) {observe(phase,kIOReturnNoMemory);return false;}
        auto *workLoop=loop;workLoop->retain();
        IOReturn rc=workLoop->runAction(startAction,this,provider);
        workLoop->release();return rc==kIOReturnSuccess;
    }
    void stop(IOService *provider) override {
        if (!provider || !loop) return;
        auto *workLoop=loop;workLoop->retain();
        workLoop->runAction(stopAction,this,provider);
        workLoop->release();
    }
    void free() override {cleanup();IOHIDDevice::free();}
};
OSDefineMetaClassAndStructors(DodgeInput,IOHIDDevice)
extern "C" IOService *dodge_input_allocate(bool touch) {
    DodgeInputStatus status={};dodge_input_status(&status);
    if (status.phase!=DodgeInputPhase::Ready) return nullptr;
    auto device=new DodgeInput;if (device && touch) device->selectTouch();return device;
}
extern "C" unsigned dodge_input_driver_bytes() {return sizeof(DodgeInput);}
extern "C" const OSMetaClass *dodge_input_driver_meta() {return DodgeInput::metaClass;}
