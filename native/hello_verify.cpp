#include <windows.h>
#include <UserConsentVerifierInterop.h>
#include <winrt/Windows.Foundation.h>
#include <winrt/Windows.Security.Credentials.UI.h>
#include <cstdlib>
#include <iostream>
#include <string>

// Desktop Windows Hello requires an owner HWND, rather than the UWP API.
// Exit codes: verified=0, declined=1, unavailable=2, internal error=3.
int wmain(int argc, wchar_t** argv) {
    if (argc != 2) return 3;
    bool availability = std::wstring(argv[1]) == L"--availability";
    HWND owner = reinterpret_cast<HWND>(_wcstoui64(argv[1], nullptr, 10));
    if (!availability && !IsWindow(owner)) return 2;
    try {
        winrt::init_apartment(winrt::apartment_type::multi_threaded);
        using namespace winrt::Windows::Security::Credentials::UI;
        if (UserConsentVerifier::CheckAvailabilityAsync().get() !=
            UserConsentVerifierAvailability::Available) return 2;
        if (availability) return 0;
        auto interop = winrt::get_activation_factory<UserConsentVerifier, IUserConsentVerifierInterop>();
        auto result = winrt::capture<winrt::Windows::Foundation::IAsyncOperation<UserConsentVerificationResult>>(
            interop, &IUserConsentVerifierInterop::RequestVerificationForWindowAsync,
            owner, reinterpret_cast<HSTRING>(winrt::get_abi(
                winrt::hstring(L"Разблокировать «Bitora password»")))).get();
        if (result == UserConsentVerificationResult::Verified) return 0;
        if (result == UserConsentVerificationResult::Canceled) return 1;
        return 2;
    } catch (winrt::hresult_error const& error) {
        std::cerr << "Windows Hello HRESULT: 0x" << std::hex << static_cast<unsigned int>(error.code().value) << std::endl;
        return 3;
    } catch (...) { return 3; }
}
