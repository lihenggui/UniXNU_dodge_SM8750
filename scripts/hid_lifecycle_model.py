#!/usr/bin/env python3
"""Explicit public IOKit peers around unchanged original iPhone HID lifetime bodies."""
import json
import struct

from check_data_mount_kernel import Model
from check_hid_parser import context, SLIDE
from native_driver_build import ROOT, require
from prepare_hid_event_abi import CONTRACT

DRIVER_INIT=0xfffffff00573e1c0
SERVICE_INIT=0xfffffff005738614
DRIVER_FREE=0xfffffff00573e210
SERVICE_FREE=0xfffffff00573a094
SERVICE_STOP=0xfffffff005739988
BLOCKS={'driver-init':(DRIVER_INIT,80),'service-init':(SERVICE_INIT,120),'driver-free':(DRIVER_FREE,0x4a8),
    'service-free':(SERVICE_FREE,0x23c),'service-stop':(SERVICE_STOP,0x1a4)}


def branch(read,pc):
    word,=struct.unpack('<I',read(pc,4));require(word&0xfc000000==0x94000000,'Original HID call changed')
    immediate=word&0x3ffffff;immediate-=1<<26 if immediate&1<<25 else 0
    return pc+4*immediate


def native_table_pointer(read):
    pc=SERVICE_INIT+16;a,b=struct.unpack('<2I',read(pc,8))
    require(a&0x9f00001f==0x90000008 and b&0xffc003ff==0xf9400108,'Original HID native-parent load changed')
    immediate=((a>>5)&0x7ffff)*4+((a>>29)&3);immediate-=1<<21 if immediate&1<<20 else 0
    return (pc&~4095)+(immediate<<12)+((b>>10)&4095)*8


class HidModel(Model):
    def __init__(self,raw,facts,*,shift=0,source=False,case='normal'):
        super().__init__(raw);self.facts=facts;self.shift=shift;self.case=case
        self.original,self.original_read,self.module,imports=context()
        self.contract=json.loads(CONTRACT.read_text());self.events=[];self.allocations={};self.freed=[];self.locks={}
        self.next_heap=self.heap+0x10000;self.typed_calls=0;self.source=source;self.original_visits=set()
        self.original_stop_calls=self.native_stops=self.native_frees=0;self.active_start=self.active_dispatch=0
        self.continuations=0;self.gate=0;self.on_native_stop=None
        self.obj,self.provider,self.loop,self.event=[self.heap+x for x in (0x1000,0x2000,0x3000,0x5000)]
        self.refs={self.obj:1,self.provider:1,self.loop:1,self.event:1};self.initial_refs=dict(self.refs)
        self.fake_table=self.scratch+0x1000;self.put(self.fake_table,bytes(219*8))
        self.string_buffer=self.heap+0x9000;self.put(self.string_buffer,b'HID lifetime fixture\0')
        self.driver_vptr=int(self.contract['classes']['IOHIDEventDriver']['vptr'],16)+shift
        self.source_vptr=self.names['__ZTV19DodgeHidEventDriver']+16 if source else self.driver_vptr
        self.root_bytes=facts['instance_bytes'] if source else 264
        self.put(self.obj-16,b'\xa5'*16+bytes(self.root_bytes)+b'\xa5'*16);self.putq(self.obj,self.source_vptr)
        for pointer in (self.provider,self.loop):self.put(pointer,bytes(128));self.putq(pointer,self.fake_table)
        self.put(self.event,bytes(80));self.putq(self.event,int(self.contract['classes']['IOHIDEvent']['vptr'],16)+shift)
        payload=self.event+0x100;self.putq(self.event+16,payload)
        p=self.contract['compiler_public_layout'];data=bytearray(p['digitizer_data_bytes'])
        struct.pack_into('<3I',data,0,len(data),11,0x20000);struct.pack_into('<2i',data,p['position'],0,32768)
        struct.pack_into('<I',data,p['index'],9);struct.pack_into('<I',data,p['mask'],2)
        struct.pack_into('<I',data,facts['digitizer_type'],2);self.put(payload,bytes(data))
        native_table=self.qword(native_table_pointer(self.original_read)+shift)
        self.parent_vptr=native_table+16
        self.peer_counter=0
        def fake(slot,name,callback):
            address=self.scratch+0x8000+16*self.peer_counter;self.peer_counter+=1
            self.peers[address]=(name,callback);self.putq(self.fake_table+slot*8,address)
        fake(4,'retain',self.retain);fake(5,'release',self.release)
        fake(18,'dictionary-count',lambda args:self.returned(0))
        fake(21,'remove-event-source',self.remove_source)
        fake(39,'cancel-timer',self.cancel_timer)
        fake(61,'registry-name',lambda args:self.returned(self.string_buffer))
        for table in (self.parent_vptr,self.driver_vptr,self.source_vptr,int(self.contract['classes']['IOHIDEvent']['vptr'],16)+shift):
            for slot,name,callback in ((4,'native-retain',self.retain),(5,'native-release',self.release),
                (61,'registry-name',lambda args:self.returned(self.string_buffer))):
                if slot==61 and table==int(self.contract['classes']['IOHIDEvent']['vptr'],16)+shift:continue
                self.peers[self.qword(table+slot*8)]=(name,callback)
        self.peers[self.qword(self.parent_vptr+21*8)]=('IOService-init',lambda args:self.returned(case!='init-parent-failure'))
        self.peers[self.qword(self.parent_vptr+87*8)]=('IOService-stop',self.native_stop)
        self.peers[self.qword(self.parent_vptr+14*8)]=('IOService-free',self.native_free)
        bindings={'_IOMallocTypeImpl':self.allocate_typed,'_IOFreeTypeImpl':self.free_typed,
            '_IORecursiveLockAlloc':lambda args:self.allocate_lock('recursive'),
            '_IOLockAlloc':lambda args:self.allocate_lock('mutex'),
            '_IORecursiveLockLock':lambda args:self.lock(args,1),'_IORecursiveLockUnlock':lambda args:self.lock(args,-1),
            '_IORecursiveLockFree':self.free_lock,'_IOLockFree':self.free_lock,
            '__ZN12OSDictionary12withCapacityEj':self.dictionary,
            '__ZN15IORegistryEntry18getRegistryEntryIDEv':lambda args:self.returned(1),
            '__os_log_internal':lambda args:self.returned(),
            '__ZNK9IOService10isInactiveEv':lambda args:self.returned(case=='inactive'),
            '__ZNK9IOService11getWorkLoopEv':lambda args:self.returned(0 if case=='no-loop' else self.loop),
            '__ZNK15OSMetaClassBase8metaCastEPKc':lambda args:self.returned(self.provider if args[0]==self.provider and case!='wrong-provider' else 0),
            '__ZNK11OSMetaClass19instanceConstructedEv':lambda args:self.returned(),
            '_PE_current_console':self.video,'_bzero':self.zero,'_memcpy':self.copy}
        for name,callback in bindings.items():
            if name in self.names:self.peers[self.names[name]]=(name,callback)
            for address,names in imports.items():
                if name in names:self.peers[address-SLIDE+shift]=(name,callback)
        # A diagnostic log-handle lookup is separate from all HID lifecycle bodies.
        self.peers[branch(self.original_read,SERVICE_STOP+0x38)+shift]=('diagnostic-log-handle',lambda args:self.returned(0))
        for name,(address,_) in BLOCKS.items():
            self.names['_hid_'+name.replace('-','_')]=address+shift
            require(address+shift not in self.peers,'A full original HID lifetime body was replaced with a peer')
        self.cpu.reg_write(self.arm.UC_ARM64_REG_CPACR_EL1,3<<20)
        self.cpu.hook_add(self.u.UC_HOOK_CODE,self.track)

    def qword(self,address):return int.from_bytes(self.read(address,8),'little')
    def putq(self,address,value):self.put(address,struct.pack('<Q',value))
    def field(self,name,value,width=1):self.put(self.obj+self.facts[name],int(value).to_bytes(width,'little'))
    def value(self,name,width=1):return int.from_bytes(self.read(self.obj+self.facts[name],width),'little')
    def track(self,cpu,pc,size,ignored):
        if pc==SERVICE_STOP+self.shift:
            require(not self.active_start and not self.active_dispatch,'Original parent stop overlapped admitted work')
            self.original_stop_calls+=1
        if pc not in self.peers and any(s['va']+self.shift<=pc<s['va']+self.shift+s['size'] for s in self.module['segments'] if s['initprot']&4):
            require(self.read(pc,size)==self.original_read(pc-self.shift,size),'Original HID lifetime instruction changed')
            self.original_visits.add(pc)
    def reserve(self,bytes_,label):
        require(0<bytes_<=4096,'Unreviewed HID allocation extent')
        pointer=self.next_heap+64;self.next_heap+=8192
        self.put(pointer-16,b'\xa5'*16+bytes(bytes_)+b'\xa5'*16)
        self.allocations[pointer]={'bytes':bytes_,'label':label};return pointer
    def allocate_typed(self,args):
        self.typed_calls+=1
        size=int.from_bytes(self.read(args[0]+self.facts['kt_size_offset'],4),'little')&self.facts['kt_size_mask']
        require(size in (376,512),'Original iPhone HID typed size changed')
        if self.case==('init-service-allocation-failure' if self.typed_calls==1 else 'init-driver-allocation-failure'):
            self.returned();return
        pointer=self.reserve(size,'service-expansion' if size==376 else 'driver-expansion')
        self.events.append('typed-allocate-'+str(size));self.returned(pointer)
    def free_typed(self,args):
        pointer=args[1];require(pointer in self.allocations and pointer not in self.freed,'HID double/foreign typed free')
        size=int.from_bytes(self.read(args[0]+self.facts['kt_size_offset'],4),'little')&self.facts['kt_size_mask']
        require(size==self.allocations[pointer]['bytes'],'Original HID typed free extent changed')
        require(self.qword(self.obj+(192 if size==376 else 256))==0,'Original HID did not erase expansion before free')
        self.freed.append(pointer);self.events.append('typed-free-'+str(size));self.returned()
    def allocate_lock(self,kind):
        pointer=self.reserve(64,kind+'-lock');self.locks[pointer]=0;self.returned(pointer)
    def lock(self,args,delta):
        require(args[0] in self.locks,'Unknown original HID lock');self.locks[args[0]]+=delta
        require(self.locks[args[0]] in (0,1),'Original HID lock recursion/unlock differs');self.returned()
    def free_lock(self,args):
        require(args[0] in self.locks and not self.locks[args[0]],'Original HID freed a held/foreign lock')
        del self.locks[args[0]];self.returned()
    def dictionary(self,args):
        require(args[0]==2,'Original HID dictionary capacity changed')
        if self.case=='init-dictionary-failure':self.returned();return
        pointer=self.resource('dictionary');self.returned(pointer)
    def resource(self,label):
        pointer=self.reserve(64,label);self.putq(pointer,self.fake_table);self.refs[pointer]=1;return pointer
    def retain(self,args):
        require(args[0] in self.refs and self.refs[args[0]]>0,'HID retained an unknown/dead object')
        self.refs[args[0]]+=1;self.returned()
    def release(self,args):
        require(args[0] in self.refs and self.refs[args[0]]>0,'HID released an unowned object')
        self.refs[args[0]]-=1;self.returned()
    def remove_source(self,args):
        require(args[0]==self.loop and args[1] in self.refs,'Original HID removed an unknown event source')
        self.events.append('remove-source');self.returned()
    def cancel_timer(self,args):
        require(args[0] in self.refs,'Original HID canceled an unknown timer')
        self.events.append('cancel-timer');self.returned()
    def native_stop(self,args):
        require(args[:2]==[self.obj,self.provider] and not self.active_start and not self.active_dispatch,'Original stop changed provider/order')
        self.native_stops+=1
        if self.on_native_stop:self.on_native_stop()
        else:self.returned()
    def native_free(self,args):
        require(args[0]==self.obj and not self.qword(self.obj+192) and not self.qword(self.obj+256) and not self.locks,
            'Original HID native parent free preceded owned cleanup')
        self.native_frees+=1;self.returned()
    def zero(self,args):
        require(0<=args[1]<=4096,'Unbounded HID zero');self.put(args[0],bytes(args[1]));self.returned()
    def copy(self,args):
        require(0<=args[2]<=4096,'Unbounded HID copy');self.put(args[0],self.read(args[1],args[2]));self.returned(args[0])
    def video(self,args):
        f=self.facts;self.put(args[0],bytes(f['video_bytes']))
        for name,value in (('width',96 if self.case=='bad-geometry' else 1440),('height',3168)):
            self.put(args[0]+f['video_'+name],value.to_bytes(f['video_'+name+'_bytes'],'little'))
        if self.case=='rotated':self.put(args[0]+f['video_rotate'],struct.pack('<I',1))
        self.returned(self.case=='video-error')
    def invoke(self,entry,args,done):
        self.continuations+=1;require(self.continuations<128,'Unbounded HID nested calls')
        returning=self.scratch+0xc000+self.continuations*16;context_=self.cpu.context_save()
        def resume(arguments):
            result=self.register(0)&0xffffffff;self.cpu.context_restore(context_);done(result)
        self.peers[returning]=('HID nested return',resume)
        self.cpu.reg_write(self.arm.UC_ARM64_REG_SP,self.cpu.reg_read(self.arm.UC_ARM64_REG_SP)-4096)
        self.cpu.reg_write(self.arm.UC_ARM64_REG_LR,returning)
        for index,value in enumerate(args):self.cpu.reg_write(getattr(self.arm,'UC_ARM64_REG_X'+str(index)),value)
        self.cpu.reg_write(self.arm.UC_ARM64_REG_PC,entry)
    def canaries(self):
        require(self.read(self.obj-16,16)==self.read(self.obj+self.root_bytes,16)==b'\xa5'*16,'HID crossed its original/selected object extent')
        for pointer,row in self.allocations.items():
            require(self.read(pointer-16,16)==self.read(pointer+row['bytes'],16)==b'\xa5'*16,'Original HID crossed an allocation extent')
