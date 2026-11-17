/*****************************************************************************
 *
 *  PROJECT:     Multi Theft Auto
 *  LICENSE:     See LICENSE in the top level directory
 *  FILE:        multiplayer_sa/CMultiplayerSA_Vehicles.cpp
 *
 *  Multi Theft Auto is available from https://www.multitheftauto.com/
 *
 *****************************************************************************/

#include "StdInc.h"

static bool __fastcall AreVehicleDoorsUndamageable(CVehicleSAInterface* vehicle)
{
    SClientEntity<CVehicleSA>* pair = pGameInterface->GetPools()->GetVehicle((DWORD*)vehicle);

    if (!pair)
        return false;

    return pair->pEntity->AreDoorsUndamageable();
}

//////////////////////////////////////////////////////////////////////////////////////////
//
// CDamageManager::ProgressDoorDamage
//
// This hook checks if our CVehicleSA instance prevents door damage
//
//////////////////////////////////////////////////////////////////////////////////////////
// >>> 0x6C2320 | 53             | push    ebx
//     0x6C2321 | 56             | push    esi
//     0x6C2322 | 0F B6 74 24 0C | movzx   esi, [esp + doorId]
//     0x6C2327 | 85 F6          | test    esi, esi
#define HOOKPOS_CDamageManager__ProgressDoorDamage  0x6C2320
#define HOOKSIZE_CDamageManager__ProgressDoorDamage 7
static DWORD CONTINUE_CDamageManager__ProgressDoorDamage = 0x6C2327;

static void _declspec(naked) HOOK_CDamageManager__ProgressDoorDamage()
{
    // clang-format off
    __asm
    {
        pushad
        mov     ecx, [esp + 08h]        // CAutomobileSAInterface*
        call    AreVehicleDoorsUndamageable
        test    al, al
        jz      continueGameCodeLocation

        popad
        mov     al, 0
        retn    8

        continueGameCodeLocation:
        popad
        push    ebx
        push    esi
        movzx   esi, [esp + 0Ch]
        jmp     CONTINUE_CDamageManager__ProgressDoorDamage
    }
    // clang-format on
}

//////////////////////////////////////////////////////////////////////////////////////////
//
// CAutomobile::GetTowHitchPos
//
// Sky Project: the game decides who can tow a trailer by the model ID (403, 514, 515, 591, the tow
// truck, the tractor). A model from engineRequestModel has its own ID, so a custom truck on a
// Roadtrain base never hitched. The check now sees the base model of such a model.
//
//////////////////////////////////////////////////////////////////////////////////////////
// >>> 0x6AF250 | 66 8B 41 22 | mov     ax, [ecx+22h]      (m_nModelIndex)
//     0x6AF254 | 83 EC 0C    | sub     esp, 0Ch
//     0x6AF257 | 66 3D 0D 02 | cmp     ax, 20Dh
#define HOOKPOS_CAutomobile__GetTowHitchPos  0x6AF250
#define HOOKSIZE_CAutomobile__GetTowHitchPos 7
static DWORD CONTINUE_CAutomobile__GetTowHitchPos = 0x6AF257;
static DWORD towHitchModel = 0;

static DWORD __cdecl GetTowHitchModel(CVehicleSAInterface* vehicle)
{
    const DWORD model = vehicle->m_nModelIndex;
    CModelInfo* modelInfo = pGameInterface->GetModelInfo(model, true);
    if (modelInfo)
    {
        const unsigned int parent = modelInfo->GetParentID();
        if (parent != 0 && parent < 65535)
            return parent;
    }
    return model;
}

static void _declspec(naked) HOOK_CAutomobile__GetTowHitchPos()
{
    // clang-format off
    __asm
    {
        pushad
        push    ecx
        call    GetTowHitchModel
        add     esp, 4
        mov     towHitchModel, eax
        popad
        mov     ax, word ptr towHitchModel
        sub     esp, 0Ch
        jmp     CONTINUE_CAutomobile__GetTowHitchPos
    }
    // clang-format on
}

//////////////////////////////////////////////////////////////////////////////////////////
//
// CMultiplayerSA::InitHooks_Vehicles
//
// Setup hooks
//
//////////////////////////////////////////////////////////////////////////////////////////
void CMultiplayerSA::InitHooks_Vehicles()
{
    EZHookInstall(CDamageManager__ProgressDoorDamage);

    // Only over the original code: a limit adjuster may have patched it
    static const BYTE original[] = {0x66, 0x8B, 0x41, 0x22, 0x83, 0xEC, 0x0C};
    if (memcmp(reinterpret_cast<const void*>(HOOKPOS_CAutomobile__GetTowHitchPos), original, sizeof(original)) == 0)
    {
        EZHookInstall(CAutomobile__GetTowHitchPos);
    }
    else
    {
        WriteDebugEvent("Sky: tow hitch hook skipped, the code at 0x6AF250 is patched");
    }
}
