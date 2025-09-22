use alloc::sync::Arc;
use core::{
    alloc::Layout,
    arch::riscv64::sfence_vma_all,
    fmt::Debug,
    ops::{Deref, DerefMut},
};

use lock_api::RawMutex;

use super::KprobeAuxiliaryOps;
use crate::{
    KprobeBasic, KprobeBuilder, KprobeOps,
    kretprobe::{KretprobeInstance, rethook_trampoline_handler},
};

// const EBREAK_INST: u32 = 0x00100073; // ebreak
const C_EBREAK_INST: u32 = 0x9002; // c.ebreak
const INSN_LENGTH_MASK: u16 = 0x3;
const INSN_LENGTH_32: u16 = 0x3;

/// The kprobe structure.
pub struct Kprobe<L: RawMutex + 'static, F: KprobeAuxiliaryOps> {
    basic: KprobeBasic<L>,
    point: Arc<Rv64KprobePoint<F>>,
}

#[derive(Debug)]
enum OpcodeTy {
    Inst16(u16),
    Inst32(u32),
}

/// The kprobe point structure for RISC-V architecture.
#[derive(Debug)]
pub struct Rv64KprobePoint<F: KprobeAuxiliaryOps> {
    addr: usize,
    old_instruction: OpcodeTy,
    inst_tmp_ptr: usize,
    _marker: core::marker::PhantomData<F>,
}

impl<L: RawMutex + 'static, F: KprobeAuxiliaryOps> Deref for Kprobe<L, F> {
    type Target = KprobeBasic<L>;

    fn deref(&self) -> &Self::Target {
        &self.basic
    }
}

impl<L: RawMutex + 'static, F: KprobeAuxiliaryOps> DerefMut for Kprobe<L, F> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.basic
    }
}

impl<L: RawMutex + 'static, F: KprobeAuxiliaryOps> Kprobe<L, F> {
    /// Get the probe point of the kprobe.
    pub fn probe_point(&self) -> &Arc<Rv64KprobePoint<F>> {
        &self.point
    }
}

impl<L: RawMutex + 'static, F: KprobeAuxiliaryOps> Debug for Kprobe<L, F> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Kprobe")
            .field("basic", &self.basic)
            .field("point", &self.point)
            .finish()
    }
}

impl<F: KprobeAuxiliaryOps> Drop for Rv64KprobePoint<F> {
    fn drop(&mut self) {
        let address = self.addr;
        match self.old_instruction {
            OpcodeTy::Inst16(inst_16) => unsafe {
                F::set_writeable_for_address(address, 2, true);
                core::ptr::write(address as *mut u16, inst_16);
                F::set_writeable_for_address(address, 2, false);
            },
            OpcodeTy::Inst32(inst_32) => unsafe {
                F::set_writeable_for_address(address, 4, true);
                core::ptr::write(address as *mut u32, inst_32);
                F::set_writeable_for_address(address, 4, false);
            },
        }
        F::dealloc_executable_memory(
            self.inst_tmp_ptr as *mut u8,
            Layout::from_size_align(8, 8).unwrap(),
        );
        unsafe {
            sfence_vma_all();
        }
        log::trace!(
            "Kprobe::uninstall: address: {:#x}, old_instruction: {:?}",
            address,
            self.old_instruction
        );
    }
}

impl<F: KprobeAuxiliaryOps> KprobeBuilder<F> {
    /// Install the kprobe and return the kprobe and its probe point.
    pub fn install<L: RawMutex + 'static>(self) -> (Kprobe<L, F>, Arc<Rv64KprobePoint<F>>) {
        let probe_point = match &self.probe_point {
            Some(point) => point.clone(),
            None => self.replace_inst(),
        };
        let kprobe = Kprobe {
            basic: KprobeBasic::from(self),
            point: probe_point.clone(),
        };
        (kprobe, probe_point)
    }

    /// Replace the instruction at the specified address with a breakpoint instruction.
    fn replace_inst(&self) -> Arc<Rv64KprobePoint<F>> {
        let address = self.symbol_addr + self.offset;
        let inst_16 = unsafe { core::ptr::read(address as *const u16) };
        // See <https://elixir.bootlin.com/linux/v6.10.2/source/arch/riscv/kernel/probes/kprobes.c#L68>
        let is_inst_16 = (inst_16 & INSN_LENGTH_MASK) != INSN_LENGTH_32;

        let inst_tmp_ptr =
            F::alloc_executable_memory(Layout::from_size_align(8, 8).unwrap()) as usize;
        let mut point = Rv64KprobePoint {
            old_instruction: OpcodeTy::Inst16(0),
            inst_tmp_ptr,
            addr: address,
            _marker: core::marker::PhantomData,
        };

        if is_inst_16 {
            point.old_instruction = OpcodeTy::Inst16(inst_16);
            unsafe {
                F::set_writeable_for_address(address, 2, true);
                core::ptr::write(address as *mut u16, C_EBREAK_INST as u16);
                F::set_writeable_for_address(address, 2, false);
                // inst_16 :0-16
                // c.ebreak:16-32
                core::ptr::write(inst_tmp_ptr as *mut u16, inst_16);
                core::ptr::write((inst_tmp_ptr + 2) as *mut u16, C_EBREAK_INST as u16);
            }
        } else {
            let inst_32 = unsafe { core::ptr::read(address as *const u32) };
            point.old_instruction = OpcodeTy::Inst32(inst_32);
            unsafe {
                F::set_writeable_for_address(address, 2, true);
                core::ptr::write(address as *mut u16, C_EBREAK_INST as _);
                F::set_writeable_for_address(address, 2, false);
                // inst_32 :0-32
                // ebreak  :32-64
                core::ptr::write(inst_tmp_ptr as *mut u32, inst_32);
                core::ptr::write((inst_tmp_ptr + 4) as *mut u16, C_EBREAK_INST as _);
            }
        }
        unsafe {
            sfence_vma_all();
        }
        log::trace!(
            "Kprobe::install: address: {:#x}, func_name: {:?}, opcode: {:x?}",
            address,
            self.symbol,
            point.old_instruction
        );
        Arc::new(point)
    }
}

impl<F: KprobeAuxiliaryOps> KprobeOps for Rv64KprobePoint<F> {
    fn return_address(&self) -> usize {
        let address = self.addr;
        match self.old_instruction {
            OpcodeTy::Inst16(_) => address + 2,
            OpcodeTy::Inst32(_) => address + 4,
        }
    }

    fn single_step_address(&self) -> usize {
        self.inst_tmp_ptr
    }

    fn debug_address(&self) -> usize {
        match self.old_instruction {
            OpcodeTy::Inst16(_) => self.inst_tmp_ptr + 2,
            OpcodeTy::Inst32(_) => self.inst_tmp_ptr + 4,
        }
    }

    fn break_address(&self) -> usize {
        self.addr
    }
}

/// Set up a single step for the given address.
///
/// This function updates the program counter (PC) to the specified address.
pub(crate) fn setup_single_step(pt_regs: &mut PtRegs, single_step_address: usize) {
    pt_regs.update_pc(single_step_address);
}

/// Clear the single step for the given address.
///
/// This function updates the program counter (PC) to the specified address.
pub(crate) fn clear_single_step(pt_regs: &mut PtRegs, single_step_address: usize) {
    pt_regs.update_pc(single_step_address);
}

/// The register state for RISC-V architecture.
#[repr(C)]
#[derive(Debug, Copy, Clone)]
#[allow(missing_docs)]
pub struct PtRegs {
    pub epc: usize,
    pub ra: usize,
    pub sp: usize,
    pub gp: usize,
    pub tp: usize,
    pub t0: usize,
    pub t1: usize,
    pub t2: usize,
    pub s0: usize,
    pub s1: usize,
    pub a0: usize,
    pub a1: usize,
    pub a2: usize,
    pub a3: usize,
    pub a4: usize,
    pub a5: usize,
    pub a6: usize,
    pub a7: usize,
    pub s2: usize,
    pub s3: usize,
    pub s4: usize,
    pub s5: usize,
    pub s6: usize,
    pub s7: usize,
    pub s8: usize,
    pub s9: usize,
    pub s10: usize,
    pub s11: usize,
    pub t3: usize,
    pub t4: usize,
    pub t5: usize,
    pub t6: usize,
    // Supervisor/Machine CSRs
    pub status: usize,
    pub badaddr: usize,
    pub cause: usize,
    // a0 value before the syscall
    pub orig_a0: usize,
}

impl PtRegs {
    pub(crate) fn break_address(&self) -> usize {
        // for riscv64
        self.epc as _
    }
    pub(crate) fn debug_address(&self) -> usize {
        self.epc as _
    }

    pub(crate) fn update_pc(&mut self, pc: usize) {
        self.epc = pc as _;
    }

    /// Get the return value from the a0 register.
    pub fn ret_value(&self) -> usize {
        self.a0
    }
}

#[unsafe(naked)]
pub(crate) unsafe extern "C" fn arch_rethook_trampoline<
    L: RawMutex + 'static,
    F: KprobeAuxiliaryOps + 'static,
>() {
    core::arch::naked_asm!(
        "addi sp, sp, -{pt_size}",
        //  Save all general-purpose registers
        "sd ra, 8(sp)",
        "sd gp, 24(sp)",
        "sd tp, 32(sp)",
        "sd t0, 40(sp)",
        "sd t1, 48(sp)",
        "sd t2, 56(sp)",
        "sd s0, 64(sp)",
        "sd s1, 72(sp)",
        "sd a0, 80(sp)",
        "sd a1, 88(sp)",
        "sd a2, 96(sp)",
        "sd a3, 104(sp)",
        "sd a4, 112(sp)",
        "sd a5, 120(sp)",
        "sd a6, 128(sp)",
        "sd a7, 136(sp)",
        "sd s2, 144(sp)",
        "sd s3, 152(sp)",
        "sd s4, 160(sp)",
        "sd s5, 168(sp)",
        "sd s6, 176(sp)",
        "sd s7, 184(sp)",
        "sd s8, 192(sp)",
        "sd s9, 200(sp)",
        "sd s10, 208(sp)",
        "sd s11, 216(sp)",
        "sd t3, 224(sp)",
        "sd t4, 232(sp)",
        "sd t5, 240(sp)",
        "sd t6, 248(sp)",
        "mv a0, sp",
        "call {callback}",
        "mv ra, a0",
        // Restore all general-purpose registers
        "ld gp, 24(sp)",
        "ld tp, 32(sp)",
        "ld t0, 40(sp)",
        "ld t1, 48(sp)",
        "ld t2, 56(sp)",
        "ld s0, 64(sp)",
        "ld s1, 72(sp)",
        "ld a0, 80(sp)",
        "ld a1, 88(sp)",
        "ld a2, 96(sp)",
        "ld a3, 104(sp)",
        "ld a4, 112(sp)",
        "ld a5, 120(sp)",
        "ld a6, 128(sp)",
        "ld a7, 136(sp)",
        "ld s2, 144(sp)",
        "ld s3, 152(sp)",
        "ld s4, 160(sp)",
        "ld s5, 168(sp)",
        "ld s6, 176(sp)",
        "ld s7, 184(sp)",
        "ld s8, 192(sp)",
        "ld s9, 200(sp)",
        "ld s10, 208(sp)",
        "ld s11, 216(sp)",
        "ld t3, 224(sp)",
        "ld t4, 232(sp)",
        "ld t5, 240(sp)",
        "ld t6, 248(sp)",
        "addi sp, sp, {pt_size}",
        "ret",
        pt_size = const core::mem::size_of::<PtRegs>(),
        callback = sym arch_rethook_trampoline_callback::<L,F>,
    )
}

pub(crate) fn arch_rethook_trampoline_callback<
    L: RawMutex + 'static,
    F: KprobeAuxiliaryOps + 'static,
>(
    pt_regs: &mut PtRegs,
) -> usize {
    rethook_trampoline_handler::<L, F>(pt_regs, pt_regs.s0)
}

pub(crate) fn arch_rethook_fixup_return(_pt_regs: &mut PtRegs, _correct_ret_addr: usize) {
    // Set the return address to the correct one
    // pt_regs.ra = correct_ret_addr; // we don't need to set ra,
}

/// Prepare the kretprobe instance for the rethook.
pub(crate) fn arch_rethook_prepare<L: RawMutex + 'static, F: KprobeAuxiliaryOps + 'static>(
    kretprobe_instance: &mut KretprobeInstance,
    pt_regs: &mut PtRegs,
) {
    // Prepare the kretprobe instance for the rethook
    kretprobe_instance.ret_addr = pt_regs.ra;
    kretprobe_instance.frame = pt_regs.s0; // fp
    pt_regs.ra = arch_rethook_trampoline::<L, F> as _; // Set the return address to the trampoline
}
