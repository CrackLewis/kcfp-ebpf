/**
 * @file bpf_wcfi_asmf.cc
 * @author CrackLewis (ghxx040406@163.com)
 * @brief
 * @version 0.1.0
 * @date 2024-12-20 13:50:38
 *
 * @copyright Copyright (c) 2024
 *
 */

#include <map>
#include <string>

std::map<std::string, bool> asm_functions = {
    {"secondary_startup_64_no_verify", true},
};

std::map<std::string, bool> exc_asm_functions = {
    {"asm_exc_divide_error", true},
    {"asm_exc_divide_error", true},
    {"asm_exc_overflow", true},
    {"asm_exc_bounds", true},
    {"asm_exc_device_not_available", true},
    {"asm_exc_coproc_segment_overrun", true},
    {"asm_exc_spurious_interrupt_bug", true},
    {"asm_exc_coprocessor_error", true},
    {"asm_exc_simd_coprocessor_error", true},
    {"asm_exc_invalid_tss", true},
    {"asm_exc_segment_not_present", true},
    {"asm_exc_stack_segment", true},
    {"asm_exc_general_protection", true},
    {"asm_exc_alignment_check", true},
    {"asm_exc_invalid_op", true},
    {"asm_exc_int3", true},
    {"asm_exc_page_fault", true},
    {"asm_exc_machine_check", true},
    {"asm_exc_nmi_noist", true},
    {"asm_exc_debug", true},
    {"asm_exc_double_fault", true},
    {"asm_exc_vmm_communication", true},
    {"asm_exc_xen_hypervisor_callback", true},
    {"asm_exc_xen_unknown_trap", true},
    {"asm_exc_nmi", true},
    {"asm_common_interrupt", true},
    {"asm_sysvec_error_interrupt", true},
    {"asm_sysvec_spurious_apic_interrupt", true},
    {"asm_sysvec_apic_timer_interrupt", true},
    {"asm_sysvec_x86_platform_ipi", true},
    {"asm_sysvec_reschedule_ipi", true},
    {"asm_sysvec_irq_move_cleanup", true},
    {"asm_sysvec_reboot", true},
    {"asm_sysvec_call_function_single", true},
    {"asm_sysvec_call_function", true},
    {"asm_sysvec_threshold", true},
    {"asm_sysvec_deferred_error", true},
    {"asm_sysvec_thermal", true},
    {"asm_sysvec_irq_work", true},
    {"asm_sysvec_kvm_posted_intr_ipi", true},
    {"asm_sysvec_kvm_posted_intr_wakeup_ipi", true},
    {"asm_sysvec_kvm_posted_intr_nested_ipi", true},
    {"asm_sysvec_hyperv_callback", true},
    {"asm_sysvec_hyperv_reenlightenment", true},
    {"asm_sysvec_hyperv_stimer0", true},
    {"asm_sysvec_xen_hvm_callback", true},
    {"asm_sysvec_kvm_asyncpf_interrupt", true},
};