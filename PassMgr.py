import sys
from Cryptodome.Protocol.KDF import scrypt
from Cryptodome.Random import get_random_bytes
from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import pad, unpad
from Cryptodome.Hash import HMAC, SHA256

encoding = 'utf-8'

# provjera integriteta datoteke koja sadži šifrirane podatke, vraća key i mac_pos
def check_mac(chiper_file, password):
    # očitavanje salt vektora i derivacija ključa iz master zaporke i salt vektora
    salt = cipher_file.read(16) 
    key = scrypt(password, salt, 32, N=2**14, r=8, p=1)

    # Čitanje pozicije na kojoj se nalazi stara oznaka
    mac_pos = int.from_bytes(cipher_file.read(16), 'big', signed=False)

    # prvih 16 bitova deriviranog ključa se koristi za određivanje mac oznake za provjeru integriteta
    mac = HMAC.new(key[0:16], digestmod=SHA256)
    cipher_file.seek(16, 0)
    mac.update(cipher_file.read(mac_pos - 16))

    # provjera mac oznake
    try:
        cipher_file.seek(mac_pos, 0)
        mac.verify(cipher_file.read())
        print ('Integrity checked')
        return key, mac_pos
    except ValueError:
        print('The password is incorrect, or the data was compromised')
        exit()

if not (len(sys.argv) == 3 and (sys.argv[1] == 'init' or sys.argv[1] == '-l') or len(sys.argv) == 4 and sys.argv[1] == 'get' or len(sys.argv) == 5 and sys.argv[1] == 'put'):
   print("No action for given parameters. Read the manual")
   exit()

# Programom se upravlja navođenjem zaporke i naredbi kao argumente prilikom pokretanja programa iz terminala 
# Naredbe "init", "get" ili "put" se predaju preko argumenata prilikom poziva programa
# Prije prvog korištenja (ili ako je došlo do narušenja integriteta), potrebno je inicijalizirati program naredbom "init"
#    Ako je sustav već inicijaliziran, ova naredba samo provjerava integritet
# Naredba "get" nakon koje slijedi glavna zaporka, a zatim adresa za koju je potrebno dohvatiti zaporku dohvaća zaporku za tu adresu i ispisuje je u terminalu
# Naredba "put" nakon koje slijedi glavna zaporka, a zatim adresa i zaporka koju treba pohraniti za tu adresu sprema par adrese i zaporke u šifriranom obliku 
# Naredba "-l" nakon koje slijedi glavna zaporka ispisuje sve adrese za koje postoji phranjena zaporka ali ne i zaporke
#    Ove tri naredbe također ponovo kriptiraju podatke sa novim ključem deriviranim iz glavne zaporke

if sys.argv[1] == 'init':
    try:
        # provjeri postoji li već datoteka sa šifriranim podacima
        # ako postoji, program samo prvojerava njen integritet
        cipher_file = open('cipher_file', 'rb+')
        mac_pos = 48
    except FileNotFoundError:
        # ako ne postoji datoteka sa šifriranim tekstom, inicijaliziraj je sa zadanom glavnom zaporkom
        salt = get_random_bytes(16)

        cipher_file = open('cipher_file', 'wb+')
        cipher_file.write(salt)
        mac_pos = 48  # spremi poziciju od koje se sprema mac
        cipher_file.write(mac_pos.to_bytes(16, 'big')) 

        # deriviraj novi ključ iz zaporke
        key = scrypt(bytes(sys.argv[2], encoding), salt, 32, N=2**14, r=8, p=1)
        
        # prva polovica deriviranog ključa (16 bajtova) se koristi za AES
        cipher = AES.new(key[16:32], AES.MODE_CBC)
        cipher_file.write(cipher.iv) # spremi inicijalizacijski vektor za AES

        # odredi i spremi oznaku integriteta
        h = HMAC.new(key[0:16], digestmod=SHA256)
        cipher_file.seek(16, 0)
        h.update(cipher_file.read()) 
        cipher_file.write(h.digest())
        cipher_file.seek(0, 0)
        
    if check_mac(cipher_file, bytes(sys.argv[2], encoding)):
        print ('Passwor Manager initialized')
    cipher_file.close()

elif sys.argv[1] == 'get' or sys.argv[1] == 'put' or sys.argv[1] == '-l':
    # probaj otvoriti šifriranu datoteku
    try:
        cipher_file = open('cipher_file', 'rb+')
    except FileNotFoundError:
        print('cipher_file missing')
        exit()
     
    # provjeri integritet
    key, mac_pos = check_mac(cipher_file, bytes(sys.argv[2], encoding))

    # dešifriraj AES
    cipher_file.seek(32, 0)
    iv = cipher_file.read(16)
    cipher_data = cipher_file.read(mac_pos - 48)
    cipher_file.close()
    cipher = AES.new(key[16:32], AES.MODE_CBC, IV=iv)

    # pohrani zaporke u listu d
    if mac_pos > 48:
        data = unpad(cipher.decrypt(cipher_data), AES.block_size)
        d = "".join(map(chr, data)).split()
    else: d = []

    # -l (argument): izlistaj sve adrese
    if sys.argv[1] == '-l':
        print('Addresses (' + str(len(d)/2) + ') :')
        for k in range (0, len(d), 2):
            print(d[k])

    p = True
    # Pronađi par adresa-zaporka i odradi get ili put naredbe
    for k in range (0, len(d) , 2):
        if len(sys.argv) > 3 and d[k] == sys.argv[3]:
            
            if sys.argv[1] == 'get':
                print('Password for', d[k], 'is', d[k+1])
            # ako od prije postoji zapis za adresu za koju se želi spremiti nova zaporka, nova zaporka se sprema umjesto stare
            elif sys.argv[1] == 'put':
                d[k+1] = sys.argv[4]
                print("Stored password for", d[k])
            p = False

    # ako ne postoji zapis za adresu za koju se želi spremiti nova zaporka, sprema se novi par adresa-zaporka
    if p :
        if sys.argv[1] == 'put':
            d.append(sys.argv[3])
            d.append(sys.argv[4])
            print("Stored passord for", sys.argv[3])

        elif sys.argv[1] == 'get':
            print("No password for the given address")
    
    # vrati listu d natrag u niz bajtova
    data = ""
    if len(d) > 0:
        for k in d:
            if len(sys.argv) > 4 and sys.argv[4].strip() == "" and k == sys.argv[3]:
                print("Password for", sys.argv[3], "deleted")
            else:
                data = data + k + " "
    data = bytes(data.strip(), encoding)
        
    # Derivacija novog ključa sa novo generiranim slučajnim vektorom salt
    salt = get_random_bytes(16)
    key = scrypt(bytes(sys.argv[2], encoding), salt, 32, N=2**14, r=8, p=1)
 
    # Šifriranje podataka pomoću AES i druge polovice novog ključa
    cipher = AES.new(key[16:32], AES.MODE_CBC)
    cipher_data = cipher.encrypt(pad(data, AES.block_size))
    mac_pos = len(cipher_data) + 48

    # Osvežavanje datoteke sa šifriranim podacima
    cipher_file = open("cipher_file", 'wb+')
    cipher_file.write(salt)
    cipher_file.write(mac_pos.to_bytes(16, 'big'))
    cipher_file.write(cipher.iv)
    cipher_file.write(cipher_data)

    # Osvježavanje oznake za provjeru integriteta
    cipher_file.seek(16, 0)
    h = HMAC.new(key[0:16], digestmod=SHA256)
    h.update(cipher_file.read())
    cipher_file.write(h.digest())
    
    cipher_file.close()