#include <windows.h>
#include <UserConsentVerifierInterop.h>
#include <winrt/Windows.Foundation.h>
#include <winrt/Windows.Security.Credentials.UI.h>
#include <cstdlib>

// Desktop Windows Hello requires an owner HWND, rather than the UWP API.
// Exit codes: verified=0, declined=1, unavailable=2, internal error=3.
int wmain(int argc, wchar_t** argv) {
    if (argc != 2) return 3;
    HWND owner = reinterpret_cast<HWND>(_wcstoui64(argv[1], nullptr, 10));
    if (!IsWindow(owner)) return 2;
    try {
        winrt::init_apartment(winrt::apartment_type::multi_threaded);
        using namespace winrt::Windows::Security::Credentials::UI;
        if (UserConsentVerifier::CheckAvailabilityAsync().get() !=
            UserConsentVerifierAvailability::Available) return 2;
        auto interop = winrt::get_activation_factory<UserConsentVerifier, IUserConsentVerifierInterop>();
        auto result = winrt::capture<winrt::Windows::Foundation::IAsyncOperation<UserConsentVerificationResult>>(
            interop, &IUserConsentVerifierInterop::RequestVerificationForWindowAsync,
            owner, winrt::get_abi(winrt::hstring(L"Разблокировать «Мои пароли»"))).get();
        return result == UserConsentVerificationResult::Verified ? 0 : 1;
    } catch (...) { return 3; }
}
