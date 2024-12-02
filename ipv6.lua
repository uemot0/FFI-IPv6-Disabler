-- ipv6.lua

-- Load the ffi module
local ffi = require("ffi")

-- Function to log debug messages
local function log_debug(message)
    fantasy.log("[IPv6_Disabler] " .. message)
end

-- Function to disable IPv6 on Windows using ffi API calls
local function disable_ipv6_windows()
    log_debug("Starting the process to disable IPv6 on Windows using ffi...")

    -- Define necessary Windows API functions and constants
    ffi.cdef[[
        typedef unsigned long DWORD;
        typedef unsigned long LONG;
        typedef const char *LPCSTR;
        typedef void *HKEY;
        typedef HKEY *PHKEY;
        typedef unsigned char BYTE;

        static const int HKEY_LOCAL_MACHINE = 0x80000002;
        static const int KEY_SET_VALUE = 0x0002;
        static const int KEY_WOW64_64KEY = 0x0100;
        static const int KEY_WRITE = 0x20006;

        LONG RegOpenKeyExA(HKEY hKey, LPCSTR lpSubKey, DWORD ulOptions, DWORD samDesired, PHKEY phkResult);
        LONG RegSetValueExA(HKEY hKey, LPCSTR lpValueName, DWORD Reserved, DWORD dwType, const BYTE *lpData, DWORD cbData);
        LONG RegCloseKey(HKEY hKey);
    ]]

    local advapi32 = ffi.load("Advapi32.dll")

    local HKEY_LOCAL_MACHINE = ffi.cast("HKEY", ffi.C.HKEY_LOCAL_MACHINE)
    local KEY_WRITE = 0x20006  -- Permissions to write to the registry
    local REG_DWORD = 4

    local subKey = "SYSTEM\\CurrentControlSet\\Services\\Tcpip6\\Parameters"
    local valueName = "DisabledComponents"
    local data = ffi.new("DWORD[1]", 0xffffffff)  -- Disable IPv6

    local phkResult = ffi.new("HKEY[1]")

    -- Open the registry key
    local res = advapi32.RegOpenKeyExA(HKEY_LOCAL_MACHINE, subKey, 0, KEY_WRITE, phkResult)
    if res ~= 0 then
        log_debug("Failed to open the registry key. Error code: " .. res)
        return false
    end

    local hKey = phkResult[0]

    -- Set the registry value
    res = advapi32.RegSetValueExA(hKey, valueName, 0, REG_DWORD, ffi.cast("const BYTE *", data), ffi.sizeof("DWORD"))
    if res ~= 0 then
        log_debug("Failed to set the registry value. Error code: " .. res)
        advapi32.RegCloseKey(hKey)
        return false
    end

    -- Close the registry key
    advapi32.RegCloseKey(hKey)

    log_debug("IPv6 has been disabled via registry settings. Please restart your computer for changes to take effect.")
    return true
end

-- Function to disable IPv6 on Linux using ffi system calls
local function disable_ipv6_linux()
    log_debug("Starting the process to disable IPv6 on Linux using ffi...")

    -- Define necessary functions to call sysctl
    ffi.cdef[[
        int sysctlbyname(const char *name, void *oldp, size_t *oldlenp, void *newp, size_t newlen);
    ]]

    -- Temporarily disable IPv6
    local value = ffi.new("int[1]", 1)

    local res = ffi.C.sysctlbyname("net.ipv6.conf.all.disable_ipv6", nil, nil, value, ffi.sizeof("int"))
    if res ~= 0 then
        log_debug("Failed to disable IPv6 via sysctlbyname for 'all'.")
        return false
    end

    res = ffi.C.sysctlbyname("net.ipv6.conf.default.disable_ipv6", nil, nil, value, ffi.sizeof("int"))
    if res ~= 0 then
        log_debug("Failed to disable IPv6 via sysctlbyname for 'default'.")
        return false
    end

    log_debug("IPv6 has been disabled via sysctl settings.")

    -- Note: To make changes persistent after reboots, editing the /etc/sysctl.conf file is required.
    -- This can be done using standard Lua file manipulation functions.

    -- Function to add lines to /etc/sysctl.conf if they don't exist
    local function append_sysctl_conf(line)
        local sysctl_file = "/etc/sysctl.conf"
        local exists = false

        -- Read the current contents of sysctl.conf
        local fh = io.open(sysctl_file, "r")
        if fh then
            for existing_line in fh:lines() do
                if existing_line:match(line) then
                    exists = true
                    break
                end
            end
            fh:close()
        end

        -- Add the line if it doesn't exist
        if not exists then
            local fh_append = io.open(sysctl_file, "a")
            if fh_append then
                fh_append:write(line .. "\n")
                fh_append:close()
                log_debug("Line added to " .. sysctl_file .. ": " .. line)
            else
                log_debug("Error opening " .. sysctl_file .. " for writing.")
                return false
            end
        else
            log_debug("Entry '" .. line .. "' already exists in " .. sysctl_file)
        end

        return true
    end

    -- Make the changes persistent by adding them to /etc/sysctl.conf
    local persistent_changes = {
        "net.ipv6.conf.all.disable_ipv6 = 1",
        "net.ipv6.conf.default.disable_ipv6 = 1"
    }

    for _, line in ipairs(persistent_changes) do
        if not append_sysctl_conf(line) then
            log_debug("Failed to add persistent configurations to disable IPv6.")
            return false
        end
    end

    -- Apply the persistent changes
    ffi.cdef[[
        int system(const char *command);
    ]]

    res = ffi.C.system("sysctl -p")
    if res ~= 0 then
        log_debug("Error applying persistent sysctl configurations.")
        return false
    end

    log_debug("IPv6 has been successfully disabled on Linux.")
    return true
end

-- Main Execution
local success = false

if fantasy.os == "windows" then
    success = disable_ipv6_windows()
elseif fantasy.os == "linux" then
    success = disable_ipv6_linux()
else
    fantasy.log("IPv6_Disabler: Unsupported operating system.")
    return false
end

-- Terminate the script after execution
if success then
    log_debug("IPv6 disabling process completed successfully. Terminating the script.")
else
    log_debug("IPv6 disabling process encountered errors. Terminating the script.")
end

return false
