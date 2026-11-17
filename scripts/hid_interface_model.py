#!/usr/bin/env python3
"""Derive original iPhone interface ownership and execute its open/close bodies."""
import struct

from hid_lifecycle_model import HidModel, branch
from native_driver_build import require


def page_address(pc,word):
    require(word&0x9f000000==0x90000000,'Original HID interface ADRP changed')
    immediate=((word>>5)&0x7ffff)*4+((word>>29)&3)
    immediate-=1<<21 if immediate&1<<20 else 0
    return (pc&~4095)+(immediate<<12)


def load_offset(word,register,base):
    require(word&0xffc003ff==0xf9400000|register|(base<<5),'Original HID interface load changed')
    return ((word>>10)&4095)*8


def derive_interface(read,compiler):
    # The original EventDriver casts its provider with this metaclass pointer.
    pc=0xfffffff00573e6d8;a,b,c=struct.unpack('<3I',read(pc,12))
    require(a&31==8 and b&0xffc003ff==0x91000108 and c==0xf9400101,'Original interface cast changed')
    meta_pointer=page_address(pc,a)+((b>>10)&4095)
    meta=struct.unpack('<Q',read(meta_pointer,8))[0]
    vptr=0xfffffff006cbf3f8;table=struct.unpack('<187Q',read(vptr,187*8))
    a,b,c=struct.unpack('<3I',read(table[7],12))
    require(a&31==0 and b&0xffc003ff==0x91000000 and c==0xd65f03c0 and
        page_address(table[7],a)+((b>>10)&4095)==meta,'Wrong original IOHIDInterface metaclass/table')
    size,=struct.unpack('<I',read(0xfffffff005735ed0+0x18,4))
    require(size&0xffe0001f==0x52800003,'Original interface metaclass extent changed')
    instance=(size>>5)&65535;require(instance==264,'Unexpected original interface allocation extent')
    opening,closing=table[168],table[89]
    require(opening==0xfffffff005736fb0 and closing==0xfffffff005737050,'Original interface open/close entries changed')
    word=lambda pc:struct.unpack('<I',read(pc,4))[0]
    reserved=load_offset(word(closing+0x20),8,0);owner=load_offset(word(closing+0x28),0,0)
    gate=load_offset(word(closing+0x50),0,8)
    require(reserved+8==instance and owner==136 and gate==24,'Original interface ownership prefix changed')
    a,b=struct.unpack('<2I',read(table[21]+0x24,8))
    require(a&31==0 and b&0xffc003ff==0x91000000,'Original interface typed allocation changed')
    view=page_address(table[21]+0x24,a)+((b>>10)&4095)
    expansion=word(view+compiler['kt_size_offset'])&compiler['kt_size_mask']
    require(56<=expansion<=512,'Unbounded original interface expansion')
    require(word(closing+0x24)&0xffc003ff==0x3900011f,'Original interface opened flag store changed')
    opened=(word(closing+0x24)>>10)&4095
    invoke=closing+0xb4
    require(word(invoke+0x10)==0xa90a7e7f and word(invoke+0x14)==0xf9004e7f,
        'Original close block no longer clears callback target/refcon/action')
    require(word(opening+0x60)==0xa90a5e93 and word(opening+0x68)==0xf9004e95,
        'Original open callback publication changed')
    pool=load_offset(word(invoke+0x1c),0,8);action=load_offset(word(invoke+0x34),0,8)
    require(pool==40 and action==8,'Original close block owned fields changed')
    driver_interface=load_offset(word(0xfffffff00573facc+0x20),0,0)
    require(driver_interface==200,'Original EventDriver weak interface field changed')
    report=table[181]
    require(load_offset(word(report),6,0)==152 and load_offset(word(report+8),8,0)==reserved and
        word(report+0x2c)==0xd61f00c0 and table[182]-report==48,'Original interface report forwarding changed')
    return {'instance_bytes':instance,'vptr':vptr,'meta':meta,'meta_pointer':meta_pointer,
        'constructor':0xfffffff005735f08,'init':table[21],'open':opening,'close':closing,
        'close_block':invoke,'run_block_stub':branch(read,closing+0x80),
        'driver_did_terminate':0xfffffff00573facc,'reserved':reserved,'owner':owner,
        'gate':gate,'opened':opened,'expansion_bytes':expansion,'callback':152,'refcon':160,'target':168,
        'pool':pool,'report_action':action,'driver_interface':driver_interface,'handle_report':report,'vtable_entries':187}


class InterfacePeers:
    """Public arbitration/command-gate peers; original interface bodies are never peers."""
    def setup_interface(self,pointer,client,*,initialized=True,owner=True):
        f=self.interface=derive_interface(self.original_read,self.facts)
        self.interface_pointer=pointer;self.interface_client=client
        self.interface_opened=set();self.interface_open_attempts=self.interface_close_calls=0
        self.interface_owner_closes=self.interface_base_closes=self.interface_flushes=0
        self.interface_gate_calls=0;self.interface_on_owner_close=None
        self.interface_on_did=None
        self.interface_fail_open=None;self.interface_termination_calls=[];self.interface_will_calls=[]
        self.interface_owner=self.heap+0xa000;self.interface_gate=self.heap+0xb000
        self.put(self.interface_owner,bytes(136));self.putq(self.interface_owner,self.parent_vptr)
        self.put(self.interface_gate,bytes(128));self.putq(self.interface_gate,self.fake_table)
        self.refs[self.interface_owner]=self.refs[self.interface_gate]=1
        self.initial_refs[self.interface_owner]=self.initial_refs[self.interface_gate]=1
        self.put(pointer-16,b'\xa5'*16+bytes(f['instance_bytes'])+b'\xa5'*16);self.putq(pointer,f['vptr']+self.shift)
        for slot in (76,77,88,90):
            require(self.qword(f['vptr']+self.shift+slot*8)==self.qword(self.parent_vptr+slot*8),
                'Original interface inherited native ABI changed at slot '+str(slot))
        if initialized:
            expansion=self.reserve(f['expansion_bytes'],'interface-expansion')
            self.putq(pointer+f['reserved'],expansion)
            self.putq(expansion+f['gate'],self.interface_gate)
        self.putq(pointer+f['owner'],self.interface_owner if owner else 0)
        for slot,name,callback in ((88,'IOService-open',self.interface_public_open),
            (89,'IOService-close',self.interface_public_close),(90,'IOService-isOpen',self.interface_is_open),
            (76,'IOService-willTerminate',self.interface_will_terminate),(77,'IOService-didTerminate',self.interface_did_terminate)):
            self.peers[self.qword(self.parent_vptr+slot*8)]=(name,callback)
        self.peers[f['run_block_stub']+self.shift]=('public-command-gate-run-block',self.interface_run_block)
        address=self.scratch+0x8100;self.putq(self.fake_table+23*8,address)
        self.peers[address]=('public-array-flush',self.interface_flush)
        for field in ('constructor','init','open','close','close_block','driver_did_terminate','handle_report'):
            require(f[field]+self.shift not in self.peers,'Original interface lifetime body is a peer: '+field)
            self.names['_interface_'+field]=f[field]+self.shift
        self.cpu.hook_add(self.u.UC_HOOK_CODE,self.interface_track)

    def interface_track(self,cpu,pc,size,ignored):
        if pc==self.interface['close']+self.shift:
            require(not self.active_start and not self.active_dispatch and not self.active_producer,
                'Interface close overlapped an admitted producer')
            self.interface_close_calls+=1
        if pc==self.interface['close_block']+self.shift:
            require(self.gate,'Original interface callback clearing escaped its gate')

    def interface_public_open(self,args):
        service,client=args[:2];require(service in (self.interface_pointer,self.interface_owner) and client in self.refs,
            'Original interface opened another client/service')
        self.interface_open_attempts+=1
        if service==self.interface_fail_open:self.returned();return
        if any(p==service and c!=client for p,c in self.interface_opened):self.returned();return
        self.interface_opened.add((service,client));self.returned(1)

    def interface_public_close(self,args):
        service,client=args[:2]
        require(service in (self.interface_pointer,self.interface_owner) and client in self.refs,
            'Original interface closed another client/service')
        self.interface_opened.discard((service,client))
        if service==self.interface_pointer:self.interface_base_closes+=1
        else:self.interface_owner_closes+=1
        if service==self.interface_owner and self.interface_on_owner_close:
            self.interface_on_owner_close()
        else:self.returned()

    def interface_is_open(self,args):
        require(args[0]==self.interface_pointer,'Source queried another interface')
        self.returned((args[0],args[1]) in self.interface_opened if args[1] else any(p==args[0] for p,c in self.interface_opened))

    def interface_run_block(self,args):
        require(args[0]==self.interface_gate,'Original interface used another command gate')
        invoke=self.qword(args[1]+16)
        require(invoke==self.interface['close_block']+self.shift and self.qword(args[1]+32)==self.interface_pointer,
            'Original interface close block/capture changed')
        self.interface_gate_calls+=1;self.gate+=1
        def done(result):self.gate-=1;self.returned(result)
        self.invoke(invoke,[args[1]],done)

    def interface_flush(self,args):
        self.interface_flushes+=1;self.returned()

    def interface_will_terminate(self,args):
        self.interface_will_calls.append(args[:3]);self.returned(self.case!='will-parent-failure')

    def interface_did_terminate(self,args):
        self.interface_termination_calls.append({'object':args[0],'provider':args[1],'options':args[2],
            'defer_on_entry':self.read(args[3],1)[0]})
        if self.interface_on_did:self.interface_on_did()
        else:self.returned(1)

    def interface_callbacks(self):
        return [self.qword(self.interface_pointer+self.interface[k]) for k in ('callback','refcon','target')]

    def interface_canaries(self):
        p=self.interface_pointer;n=self.interface['instance_bytes']
        require(self.read(p-16,16)==self.read(p+n,16)==b'\xa5'*16,'Original interface crossed its measured extent')


class InterfaceModel(InterfacePeers,HidModel):
    def __init__(self,raw,facts,case):
        super().__init__(raw,facts,case=case)
        self.setup_interface(self.obj,self.provider,initialized=False,owner=case!='no-owner')
        if case=='init-parent-failure':
            self.peers[self.qword(self.parent_vptr+21*8)]=('native-init-failure',lambda args:self.returned())
    def allocate_typed(self,args):
        size=int.from_bytes(self.read(args[0]+self.facts['kt_size_offset'],4),'little')&self.facts['kt_size_mask']
        require(size==self.interface['expansion_bytes'],'Original interface allocation metadata changed')
        if self.case=='init-allocation-failure':self.returned();return
        self.returned(self.reserve(size,'interface-expansion'))
