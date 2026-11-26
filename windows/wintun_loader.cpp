// Pulse VPN - Windows Wintun Driver Loader Implementation
// windows/wintun_loader.cpp

#include "wintun_loader.h"

// Pulse VPN deterministic adapter GUID: {6B84F2A1-4E53-4A9E-9A7D-2C3E4F5A6B7C}
static const GUID kPulseVpnAdapterGuid = {
    0x6b84f2a1, 0x4e53, 0x4a9e, {0x9a, 0x7d, 0x2c, 0x3e, 0x4f, 0x5a, 0x6b, 0x7c}
};

WintunDriverLoader::WintunDriverLoader() = default;

WintunDriverLoader::~WintunDriverLoader() {
    StopTunnelSession();
    if (wintunModule_ != nullptr) {
        FreeLibrary(wintunModule_);
        wintunModule_ = nullptr;
    }
}

bool WintunDriverLoader::InitializeDriver() {
    if (wintunModule_ != nullptr) {
        return true;
    }

    wintunModule_ = LoadLibraryExW(
        L"wintun.dll",
        nullptr,
        LOAD_LIBRARY_SEARCH_APPLICATION_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32);

    if (wintunModule_ == nullptr) {
        return false;
    }

    CreateAdapter = reinterpret_cast<WINTUN_CREATE_ADAPTER_FUNC>(
        GetProcAddress(wintunModule_, "WintunCreateAdapter"));
    OpenAdapter = reinterpret_cast<WINTUN_OPEN_ADAPTER_FUNC>(
        GetProcAddress(wintunModule_, "WintunOpenAdapter"));
    CloseAdapter = reinterpret_cast<WINTUN_CLOSE_ADAPTER_FUNC>(
        GetProcAddress(wintunModule_, "WintunCloseAdapter"));
    StartSession = reinterpret_cast<WINTUN_START_SESSION_FUNC>(
        GetProcAddress(wintunModule_, "WintunStartSession"));
    EndSession = reinterpret_cast<WINTUN_END_SESSION_FUNC>(
        GetProcAddress(wintunModule_, "WintunEndSession"));
    ReceivePacket = reinterpret_cast<WINTUN_RECEIVE_PACKET_FUNC>(
        GetProcAddress(wintunModule_, "WintunReceivePacket"));
    ReleaseReceivePacket = reinterpret_cast<WINTUN_RELEASE_RECEIVE_PACKET_FUNC>(
        GetProcAddress(wintunModule_, "WintunReleaseReceivePacket"));
    AllocateSendPacket = reinterpret_cast<WINTUN_ALLOCATE_SEND_PACKET_FUNC>(
        GetProcAddress(wintunModule_, "WintunAllocateSendPacket"));
    SendPacket = reinterpret_cast<WINTUN_SEND_PACKET_FUNC>(
        GetProcAddress(wintunModule_, "WintunSendPacket"));

    if (!CreateAdapter || !OpenAdapter || !CloseAdapter ||
        !StartSession || !EndSession || !ReceivePacket ||
        !ReleaseReceivePacket || !AllocateSendPacket || !SendPacket) {
        FreeLibrary(wintunModule_);
        wintunModule_ = nullptr;
        return false;
    }

    return true;
}

bool WintunDriverLoader::CreatePulseAdapter(const wchar_t* adapterName) {
    if (!InitializeDriver()) {
        return false;
    }

    adapter_ = OpenAdapter(adapterName);
    if (adapter_ == nullptr) {
        adapter_ = CreateAdapter(adapterName, L"WireGuard", &kPulseVpnAdapterGuid);
    }
    return adapter_ != nullptr;
}

bool WintunDriverLoader::StartTunnelSession(DWORD ringCapacity) {
    if (adapter_ == nullptr && !CreatePulseAdapter()) {
        return false;
    }
    session_ = StartSession(adapter_, ringCapacity);
    return session_ != nullptr;
}

void WintunDriverLoader::StopTunnelSession() {
    if (session_ != nullptr && EndSession != nullptr) {
        EndSession(session_);
        session_ = nullptr;
    }
    if (adapter_ != nullptr && CloseAdapter != nullptr) {
        CloseAdapter(adapter_);
        adapter_ = nullptr;
    }
}
