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



#include <hve/arch/intel_x64/vcpu.h>
#include <bfdebug.h>
#include <bfcallonce.h>
#include <string>
#include <sstream>
#include "json.hpp"

using namespace bfvmm::intel_x64;
using nlohmann::json;

typedef enum hstatus {
    HSTATUS_SUCCESS = 0ull,
    HSTATUS_FAILURE
} hstatus_t;

#define HCALL_INVALID       0
#define HCALL_ACK           1
#define HCALL_GET_REGISTERS 2
#define HCALL_SET_REGISTERS 3
#define HCALL_TRANSLATE_V2P 4
#define HCALL_MAP_PA        5

ept::mmap g_guest_map{};

void hcall_memmap_ept(vcpu_t *vcpu)
{
    uint64_t addr = vcpu->rdi();
    uint64_t gpa2 = vcpu->rsi();

    auto hpa = vcpu->gva_to_gpa(addr);
    auto gpa1 = hpa.first;

    if(g_guest_map.is_2m(gpa1))
    {
        auto gpa1_2m = bfn::upper(gpa1, ::intel_x64::ept::pd::from);
        ept::identity_map_convert_2m_to_4k(g_guest_map, gpa1_2m);
    }

    auto gpa1_4k = bfn::upper(gpa1, ::intel_x64::ept::pt::from);
    auto gpa2_4k = bfn::upper(gpa2, ::intel_x64::ept::pt::from);

    vcpu->set_rsi(gpa2_4k);

    auto pte = g_guest_map.entry(gpa1_4k);
    ::intel_x64::ept::pt::entry::phys_addr::set(pte.first, gpa2_4k);

    // flush EPT tlb, guest TLB doesn't need to be flushed
    // as that translation hasn't changed
    ::intel_x64::vmx::invept_global();

    bfdebug_info(0, "memmap ept called");
}

void hcall_translate_v2p(vcpu_t *vcpu)
{
    auto addr = vcpu->rdi();
    auto hpa = vcpu->gva_to_gpa(addr);

    vcpu->set_rdi(hpa.first);

    bfdebug_info(0, "v2p vmcall handled");
}

void hcall_get_register_data(vcpu_t *vcpu)
{
    bfdebug_info(0, "hcall_get_register_data start");
    json j;
    j["RAX"] = vcpu->rax();
    j["RBX"] = vcpu->rbx();
    j["RCX"] = vcpu->rcx();
    j["RDX"] = vcpu->rdx();
    j["R08"] = vcpu->r08();
    j["R09"] = vcpu->r09();
    j["R10"] = vcpu->r10();
    j["R11"] = vcpu->r11();
    j["R12"] = vcpu->r12();
    j["R13"] = vcpu->r13();
    j["R14"] = vcpu->r14();
    j["R15"] = vcpu->r15();
    j["RBP"] = vcpu->rbp();
    j["RSI"] = vcpu->rsi();
    j["RDI"] = vcpu->rdi();
    j["RIP"] = vcpu->rip();
    j["RSP"] = vcpu->rsp();
    j["CR0"] = ::intel_x64::vmcs::guest_cr0::get();
    j["CR3"] = ::intel_x64::vmcs::guest_cr3::get();
    j["CR4"] = ::intel_x64::vmcs::guest_cr4::get();
    j["MSR_EFER"] = ::intel_x64::vmcs::guest_ia32_efer::get();

    uintptr_t addr = vcpu->rdi();
    uint64_t size = vcpu->rsi();

    auto omap = vcpu->map_gva_4k<char>(addr, size);

    auto &&dmp = j.dump();

    __builtin_memcpy(omap.get(), dmp.data(), size);

    bfdebug_info(0, "get-registers vmcall handled");
}

void global_init()
{
    bfdebug_info(0, "running libvmi example");
    bfdebug_lnbr(0);

    ept::identity_map(
        g_guest_map, MAX_PHYS_ADDR
    );
}

bool vmcall_handler(vcpu_t *vcpu)
{
    guard_exceptions([&] {
        switch (vcpu->rax())
        {
            case HCALL_TRANSLATE_V2P:
                bfdebug_info(0, "HCALL_TRANSLATE_V2P in");
                hcall_translate_v2p(vcpu);
                break;
            case HCALL_GET_REGISTERS:
                bfdebug_info(0, "HCALL_GET_REGISTERS in");
                hcall_get_register_data(vcpu);
                break;
            case HCALL_MAP_PA:
                bfdebug_info(0, "HCALL_MAP_PA in");
                hcall_memmap_ept(vcpu);
                break;
            default:
                bfalert_nhex(0, "unknown vmcall", vcpu->rax());
                break;
        };

        vcpu->set_rax(HSTATUS_SUCCESS);
    },
    [&] {
        bfdebug_info(0, "guard guard_exceptions in 2");
        vcpu->set_rax(HSTATUS_FAILURE);
    });

    return vcpu->advance();
}

bool cpuid_magic(vcpu_t *vcpu)
{
    if ( vcpu->rax() == 0x40001337 )
    {
        bfdebug_info(0, "cpuid_magic adding values");
        vcpu->set_rax(42);
        vcpu->set_rbx(42);
        vcpu->set_rcx(42);
        vcpu->set_rdx(42);
        return vcpu->advance();
    }

    return false;
}


void vcpu_init_nonroot(vcpu_t *vcpu)
{
    using namespace vmcs_n::exit_reason;

    vcpu->set_eptp(g_guest_map);
    vcpu->add_handler(basic_exit_reason::vmcall, vmcall_handler);
    vcpu->add_handler(basic_exit_reason::cpuid, cpuid_magic);
}
