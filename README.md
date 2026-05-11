# GoCryptFS Hashcat Plugin
GoCryptFS Hashcat Plugin

Setup
- put gocryptfs_hkdf_FT.py in HASHCAT_ROOT/Python/
- put your .conf in HASHCAT_ROOT/Python/ or provide the path to it in the passed hash
  <br>hash format = `gocryptfs*Z:path/to/your/gocryptfs.conf`

Example 1 Usage (for CMD)
```
hashcat -m 72000 gocryptfs*.\Python\gocryptfs.conf ^
--bridge-parameter1 .\Python\gocryptfs_hkdf_FT.py ^
-a 3 ?d?d?d?d -w 3
```

Outputs the following for success case for the conf file in prev comment
```
✅ PASSWORD FOUND: 4321
Masterkey: 3e5dd7732b86f0f804cc89b966dbfb3047d9293b670aa88a58b7621d7967db87
```

<details><summary>Example 2 Usage (for CMD)</summary>
<p>

```
hashcat -z --brain-password=admin --brain-client-features=3 ^
-m 72000 gocryptfs*C:\Users\Public\Downloads\gocryptfs.conf ^
--bridge-parameter1 .\Python\gocryptfs_hkdf_FT.py ^
-a 3 ?d?d?d?d -w 3
```

</p>
</details> 



For an 8 core CPU it can get the following perf
```
Hash.Mode........: 72000 (Generic Hash [Bridged: Python Interpreter free-threading])
...
Speed.#*.........:       98 H/s
``` 

Further improvement needs GPU cuda/opencl plugin module.
