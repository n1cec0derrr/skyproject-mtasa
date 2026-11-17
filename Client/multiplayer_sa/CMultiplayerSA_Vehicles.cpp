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
// Roadtrain base never hitched. For the time of the call the vehicle gets the ID of its base model.
//
// The function itself (0x6AF250) is patched by the limit adjuster, so its code is not touched:
// the entries of the virtual tables that point at it are replaced by a wrapper that calls
// whatever was there.
//
//////////////////////////////////////////////////////////////////////////////////////////
namespace
{
    // CAutomobile and the classes that inherit its GetTowHitchPos
    const DWORD towHitchVtableSlots[] = {0x871210, 0x871770, 0x8718C8, 0x871A38, 0x871BD8};

    using GetTowHitchPos_t = bool(__thiscall*)(CVehicleSAInterface*, CVector*, bool, void*);
    GetTowHitchPos_t originalGetTowHitchPos = nullptr;

    bool __fastcall GetTowHitchPos_Wrapper(CVehicleSAInterface* vehicle, void*, CVector* position, bool checkModelInfo, void* other)
    {
        const unsigned short model = vehicle->m_nModelIndex;
        unsigned short       parent = 0;

        if (CModelInfo* modelInfo = pGameInterface->GetModelInfo(model, true))
        {
            const unsigned int id = modelInfo->GetParentID();
            if (id != 0 && id < 65535)
                parent = static_cast<unsigned short>(id);
        }

        if (!parent)
            return originalGetTowHitchPos(vehicle, position, checkModelInfo, other);

        vehicle->m_nModelIndex = parent;
        const bool result = originalGetTowHitchPos(vehicle, position, checkModelInfo, other);
        vehicle->m_nModelIndex = model;
        return result;
    }
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

    // Custom truck models hitch trailers like their base model
    originalGetTowHitchPos = *reinterpret_cast<GetTowHitchPos_t*>(towHitchVtableSlots[0]);
    int replaced = 0;
    for (DWORD slot : towHitchVtableSlots)
    {
        if (*reinterpret_cast<GetTowHitchPos_t*>(slot) != originalGetTowHitchPos)
            continue;  // something else is there: leave it
        MemPut<DWORD>(slot, reinterpret_cast<DWORD>(&GetTowHitchPos_Wrapper));
        replaced++;
    }
    WriteDebugEvent(SString("Sky: tow hitch wrapper in %d vtables, original %08X", replaced, reinterpret_cast<DWORD>(originalGetTowHitchPos)));
}
