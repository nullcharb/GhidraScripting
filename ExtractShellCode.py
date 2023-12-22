import os
startAddress = toAddr(0x14000a000)  
shellcodeLength = 0x11B
output_array = ""
outputFilePath = "C:\\Users\\Developer\\Desktop\\GhidraScripting\\shellcode.bin"  
with open(outputFilePath, "wb") as outputFile:
    currentAddress = startAddress
    for _ in range(shellcodeLength):
        currentByte = getByte(currentAddress)
        output_array = output_array + (chr(currentByte & 0xff))
        print(f"Current Byte : {chr(currentByte & 0xff).encode()}, type : {type(chr(currentByte & 0xff))}")
        currentAddress = currentAddress.next()
    print(bytes(output_array, encoding="raw_unicode_escape"))
    outputFile.write(bytes(output_array, encoding="raw_unicode_escape"))