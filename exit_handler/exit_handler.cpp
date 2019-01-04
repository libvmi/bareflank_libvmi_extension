// // Bareflank Extended APIs
// Copyright (C) 2018 Assured Information Security, Inc.
//
// This library is free software; you can redistribute it and/or
// modify it under the terms of the GNU Lesser General Public
// License as published by the Free Software Foundation; either
// version 2.1 of the License, or (at your option) any later version.
//
// This library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
// Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public
// License along with this library; if not, write to the Free Software
// Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA

#include <bfvmm/vcpu/vcpu_factory.h>
#include <bfvmm/hve/arch/intel_x64/vcpu.h>
#include <bfvmm/hve/arch/intel_x64/exit_handler.h>
#include <bfdebug.h>
#include <bfvmm/memory_manager/buddy_allocator.h>
#include <bfvmm/memory_manager/arch/x64/unique_map.h>
#include "json.hpp"
#include <stdlib.h>
#include <string.h>
#include <eapis/hve/arch/intel_x64/vcpu.h>
#include <eapis/hve/arch/intel_x64/vmexit/cpuid.h>
#include <bfcallonce.h>

using nlohmann::json;
using namespace eapis::intel_x64;

namespace libvmi
{

typedef enum hstatus {
    HSTATUS_SUCCESS = 0ull,
    HSTATUS_FAILURE
} hstatus_t;

typedef enum hcall {
    HCALL_ACK = 1ull,
    HCALL_GET_REGISTERS,
    HCALL_SET_REGISTERS,
    HCALL_TRANSLATE_V2P,
    HCALL_MAP_PA
} hcall_t;


bfn::once_flag flag{};
ept::mmap g_guest_map;

void create_ept(void)
{
    ept::identity_map(g_guest_map, MAX_PHYS_ADDR);
    ::intel_x64::vmx::invept_global();
}

class vcpu : public eapis::intel_x64::vcpu
{

public:

    using handler_t = bool(gsl::not_null<bfvmm::intel_x64::vmcs *>);
    using handler_delegate_t = delegate<handler_t>;

    ~vcpu() = default;
    vcpu(vcpuid::type id) : eapis::intel_x64::vcpu{id}
    {
        bfn::call_once(flag, [&] {
            create_ept();
        });

    	eapis()->set_eptp(g_guest_map);

        exit_handler()->add_handler(
            intel_x64::vmcs::exit_reason::basic_exit_reason::vmcall,
            handler_delegate_t::create<vcpu, &vcpu::vmcall_handler>(this)
        );

        eapis()->add_cpuid_handler(
            0x40001337,
            cpuid_handler::handler_delegate_t::create<vcpu, &vcpu::cpuid_handler>(this)
        );
    }

    bool cpuid_handler(gsl::not_null<vmcs_t *> vmcs, cpuid_handler::info_t &info) {
        info.rax = 42;
        info.rbx = 42;
        info.rcx = 42;
        info.rdx = 42;
        return true;
    }

    bool vmcall_handler(gsl::not_null<bfvmm::intel_x64::vmcs *> vmcs) {

        uint64_t hcall = vmcs->save_state()->rax;

        guard_exceptions([&] {
            switch ( hcall ) {
                case HCALL_ACK:
                    create_ept(); // reset EPT
                    bfdebug_info(0, "vmcall handled");
                break;
                case HCALL_GET_REGISTERS:
                    hcall_get_register_data(vmcs);
                    break;
                case HCALL_SET_REGISTERS:
                    break;
                case HCALL_TRANSLATE_V2P:
                    hcall_translate_v2p(vmcs);
                    break;
                case HCALL_MAP_PA:
                    hcall_memmap_ept(vmcs);
                    break;
                default:
                    break;
            };

            vmcs->save_state()->rax = HSTATUS_SUCCESS;
        },
        [&] {
            vmcs->save_state()->rax = HSTATUS_FAILURE;
        });

        //else if (id == 5) {
        //    get_memmap_ept(vmcs);
        //}
    	return advance(vmcs);
    }

    void hcall_get_register_data(gsl::not_null<bfvmm::intel_x64::vmcs *> vmcs) {
        json j;
        j["RAX"] = vmcs->save_state()->rax;
        j["RBX"] = vmcs->save_state()->rbx;
        j["RCX"] = vmcs->save_state()->rcx;
        j["RDX"] = vmcs->save_state()->rdx;
        j["R08"] = vmcs->save_state()->r08;
        j["R09"] = vmcs->save_state()->r09;
        j["R10"] = vmcs->save_state()->r10;
        j["R11"] = vmcs->save_state()->r11;
        j["R12"] = vmcs->save_state()->r12;
        j["R13"] = vmcs->save_state()->r13;
        j["R14"] = vmcs->save_state()->r14;
        j["R15"] = vmcs->save_state()->r15;
        j["RBP"] = vmcs->save_state()->rbp;
        j["RSI"] = vmcs->save_state()->rsi;
        j["RDI"] = vmcs->save_state()->rdi;
        j["RIP"] = vmcs->save_state()->rip;
        j["RSP"] = vmcs->save_state()->rsp;
        j["CR0"] = ::intel_x64::vmcs::guest_cr0::get();
        j["CR3"] = ::intel_x64::vmcs::guest_cr3::get();
        j["CR4"] = ::intel_x64::vmcs::guest_cr4::get();
        j["MSR_EFER"] = ::intel_x64::vmcs::guest_ia32_efer::get();
        /*//TODO:
         * DR0-DR7 debug registers
         * segment resisters
         * MSR registers
         * complete list at https://github.com/boddumanohar/libvmi/blob/master/libvmi/libvmi.h
        */
        uintptr_t addr = vmcs->save_state()->rdi;
        uint64_t size = vmcs->save_state()->rsi;

        // create memory map for the buffer in bareflank
        auto omap = bfvmm::x64::make_unique_map<char>(addr,
                    ::intel_x64::vmcs::guest_cr3::get(),
                    size
                    );

        auto &&dmp = j.dump();
        __builtin_memcpy(omap.get(), dmp.data(), size);

        bfdebug_info(0, "get-registers vmcall handled");
    }

    void hcall_translate_v2p(gsl::not_null<bfvmm::intel_x64::vmcs *> vmcs) {
        auto addr = vmcs->save_state()->rdi;
        auto cr3 = intel_x64::vmcs::guest_cr3::get();

        addr = bfvmm::x64::virt_to_phys_with_cr3(addr, cr3);

        vmcs->save_state()->rdi = addr;

        bfdebug_info(0, "v2p vmcall handled");
    }

// (dummy buffer)addr -> gpa1 -> hpa1
//                       gpa2 -> hpa2
//
// To goal is to use EPT and make addr point to hpa2 instead of hpa1

    void hcall_memmap_ept(gsl::not_null<bfvmm::intel_x64::vmcs *> vmcs) {

        uint64_t addr = vmcs->save_state()->rdi;
        uint64_t gpa2 = vmcs->save_state()->rsi;

        auto cr3 = intel_x64::vmcs::guest_cr3::get();
        auto gpa1 = bfvmm::x64::virt_to_phys_with_cr3(addr, cr3);

        if ( g_guest_map.is_2m(gpa1) ) {
            /* Change EPT from 2m to 4k */
            auto gpa1_2m = bfn::upper(gpa1, ::intel_x64::ept::pd::from);
            ept::identity_map_convert_2m_to_4k(g_guest_map, gpa1_2m);
        }

        auto gpa1_4k = bfn::upper(gpa1, ::intel_x64::ept::pt::from);
        auto gpa2_4k = bfn::upper(gpa2, ::intel_x64::ept::pt::from);

        vmcs->save_state()->rsi = gpa2_4k;

        auto &pte = g_guest_map.entry(gpa1_4k);
        ::intel_x64::ept::pt::entry::phys_addr::set(pte, gpa2_4k);

        // flush EPT tlb, guest TLB doesn't need to be flushed
        // as that translation hasn't changed
        ::intel_x64::vmx::invept_global();
    }
};

}

// -----------------------------------------------------------------------------
// vCPU Factory
// -----------------------------------------------------------------------------

namespace bfvmm
{

std::unique_ptr<vcpu>
vcpu_factory::make(vcpuid::type vcpuid, bfobject *obj)
{
    bfignored(obj);
    return std::make_unique<libvmi::vcpu>(vcpuid);
}

}
