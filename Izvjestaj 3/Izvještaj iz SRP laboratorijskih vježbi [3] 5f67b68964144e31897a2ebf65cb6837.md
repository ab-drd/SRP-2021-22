# Izvještaj iz SRP laboratorijskih vježbi [3]

## Message authentication and integrity

U 3. vježbi cilj je bio testirati gradivo naučeno na predavanjima kroz nekoliko izazova. Koristili smo simetrične i asimetrične kripto mehanizme — *message authentication code* (MAC) i *digitalne potpise* temeljene na javnim ključevima.

## Izazov 1

Zadatak ovog izazova bio je implementirati zaštitu integriteta poruke primjenom odgovarajućeg MAC algoritma. Odabarali smo HMAC mehanizam iz Python-ove biblioteke `cryptography`.

Aktivacija virtualnog okruženja:

```bash
C:\Users\A507\ab\vjezba3\abartu\Scripts>activate

(abartu) C:\Users\A507\ab\vjezba3\abartu\Scripts>cd ..

(abartu) C:\Users\A507\ab\vjezba3\abartu>cd ..

(abartu) C:\Users\A507\ab\vjezba3>code message_integrity.py
```

Kod za generiranje MAC-a temeljenog na zadanom ključu i poruci:

```python
from cryptography.hazmat.primitives import hashes, hmac

def generate_MAC(key, message):
    if not isinstance(message, bytes):
        message = message.encode()

    h = hmac.HMAC(key, hashes.SHA256())
    h.update(message)
    signature = h.finalize()
    return signature

if __name__ == "__main__":
    key = b"vokaJ"
    message = "Volim Jakova Beju >:)"
    mac_value = generate_MAC(key, message)
    print(mac_value.hex())

    pass
```

Output gornjeg programa:

```bash
(abartu) C:\Users\A507\ab\vjezba3>python .\message_integrity.py
7cfa9749335a5f58f9f0477a020b5766e9c11b9e95fcddbd612df30240b3b72c
```

Funkcija za provjeru validnosti poruke:

```python
from cryptography.exceptions import InvalidSignature

def verify_MAC(key, signature, message):
    if not isinstance(message, bytes):
        message = message.encode()

    h = hmac.HMAC(key, hashes.SHA256())
    h.update(message)

		try:
        h.verify(signature)
    except InvalidSignature:
        return False
    else:
        return True
```

Modificiramo main message_integrity.py da izgleda ovako:

```python
if __name__ == "__main__":
    key = b"vokaJ"
    message = "Volim Jakova Beju >:)"
    mac_value = generate_MAC(key, message)
    print(mac_value.hex())

    verification = verify_MAC(key, mac_value, message)
    print(verification)
    
    pass
```

Naš output sad izgleda ovako:

```bash
(abartu) C:\Users\A507\ab\vjezba3>python .\message_integrity.py
7cfa9749335a5f58f9f0477a020b5766e9c11b9e95fcddbd612df30240b3b72c
True
```

Očito je da smo i trebali dobiti True, pošto nismo mijenjali ključne vrijednosti, odnosno ključ, poruku i dobivenu MAC vrijednost.

### Čitanje i pisanje u datoteke

Ponovno modificiramo main `message_integrity.py` programa kako bismo omogućili čitanje iz i pisanje u datoteku:

```python
if __name__ == "__main__":
    key = b"vokaJ"
    with open("protect.txt", "rb") as file:
        content = file.read()

    mac = generate_MAC(key, content)
    with open("protect.sig", "wb") as file:
        file.write(mac)

    pass
```

U datoteku `protect.txt` napisali smo poruku koju želimo čuvati u tekstualnom obliku, a u datoteku `protect.sig` spremamo MAC generiran na temelju sadržaja iz .txt datoteke.

### Testiranje validiteta modificiranih datoteka

Promijenimo li sadržaj `protect.txt` ili `protect.sig` datoteka pomoću heksadekadskog editora te zatim pokrenemo program, funkcija `verify_MAC` dat će nam False output.

## Izazov 2

Cilj izazova 2 bio je utvrditi vremenski ispravnu sekvencu transakcija s odgovarajućim dionicama. Datoteke koje smo morali provjeriti postavljene su na lokalnom web poslužitelju za učionicu: [http://a507-server.local](http://a507-server.local/), a kako ne bismo ručno morali skidati sve datoteke (stvarno ih je puno!) iskoristili smo program **wget**.

Izvršavanjem sljedećeg koda:

```bash
wget.exe -r -nH -np --reject "index.html*" http://a507-server.local/challenges/<bartulovic_antonia>/
```

naši su se podaci magično preuzeli točno gdje su i trebali.

Za ovaj izazov ključ je generiran na sljedeći način:

```python
key = "bartulovic_antonia".encode()
```

odnosno korištenjem enkodiranog imena i prezimena studenta.

Želimo napraviti kod koji će vrtiti loop koji će izlistati savjete za kupovinu kronološki. Zaključujemo da treba otvoriti sve datoteke, te preko `verify_MAC` funkcije provjeravati autentičnost parova .txt i .sig datoteka, uz gore generirani ključ. Invalidne ćemo datoteke odbaciti, a one koje prođu funkciju sa True dodat ćemo u listu koju ćemo zatim morati sortirati po vremenu.

Loop za šetanje po datotekama i provjeru njihove autentičnosti:

```python
for ctr in range(1, 11):
    msg_filename = f"order_{ctr}.txt"
    sig_filename = f"order_{ctr}.sig"    
    with open(msg_filename, "rb") as file:
            content = file.read()  
    with open(sig_filename, "rb") as file:
            signature = file.read()

    is_authentic = verify_MAC(key, signature, content)

    print(f'Message {message.decode():>45} {"OK" if is_authentic else "NOK":<6}')
```

Cjeloviti kod:

```python
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.exceptions import InvalidSignature

def generate_MAC(key, message):
    if not isinstance(message, bytes):
        message = message.encode()
    h = hmac.HMAC(key, hashes.SHA256())
    h.update(message)
    signature = h.finalize()
    return signature

def verify_MAC(key, signature, message):
    if not isinstance(message, bytes):
        message = message.encode()

    h = hmac.HMAC(key, hashes.SHA256())
    h.update(message)
    try:
        h.verify(signature)
    except InvalidSignature:
        return False
    else:
        return True

if __name__ == "__main__":

    for ctr in range(1,11):
        msg_filename = f"order_{ctr}.txt"
        sig_filename = f"order_{ctr}.sig"
        with open(msg_filename, "rb") as file:
            content = file.read()  
        with open(sig_filename, "rb") as file:
            signature = file.read() 

        key = "bartulovic_antonia".encode()
        is_authentic = verify_MAC(key, signature, content)

        print(f'Message {content.decode():>45} {"OK" if is_authentic else "NOK":<6}')
```

---

## Digitalni potpisi pomoću public-key kriptografije

U ovom dijelu vježbe zadane su nam dvije slike, među kojima trebamo odrediti autentičnu. One su naizgled iste, ali jedna je od njih modificirana te se tako njen novi potpis ne slaže s već napravljenim. Profesor je potpise napravio koristeći privatni ključ, a na nama je bilo iskoristiti javni na neki način.

Taj neki način je sljedeći: koristeći javni ključ, dekriptirat ćemo .sig datoteku. Integritet te datoteke je sačuvan, jer ju je enkriptirao vlasnik privatnog ključa, u ovom slučaju profesor. Dobijemo hash vrijednost koja je ili nije ona koju bismo dobili kad bismo hashirali odgovarajuću sliku. Za nas ovo obavi funkcija PUBLIC_KEY.verify().

Iz datoteke učitatavamo javni ključ na sljedeći način:

```python
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

def load_public_key():
    with open("public.pem", "rb") as f:
        PUBLIC_KEY = serialization.load_pem_public_key(
            f.read(),
            backend=default_backend()
        )
    return PUBLIC_KEY

if __name__ == "__main__":

    public = load_public_key();
    print(public)
```

Ispravnost digitalnog potpisa provjerava se sljedećom funkcijom:

```python
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidSignature

def verify_signature_rsa(signature, message):
    PUBLIC_KEY = load_public_key()
    try:
        PUBLIC_KEY.verify(
            signature,
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
    except InvalidSignature:
        return False
    else:
        return True
```

Završeni kod:

```python
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidSignature

def load_public_key():
    with open("public.pem", "rb") as f:
        PUBLIC_KEY = serialization.load_pem_public_key(
            f.read(),
            backend=default_backend()
        )
    return PUBLIC_KEY

def verify_signature_rsa(signature, message):
    PUBLIC_KEY = load_public_key()
    try:
        PUBLIC_KEY.verify(
            signature,
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )

    except InvalidSignature:
        return False
    else:
        return True

if __name__ == "__main__":

    public = load_public_key();

    print(public)

if __name__ == "__main__":

    with open("image_1.png", "rb") as file:
        image = file.read()
    with open("image_1.sig", "rb") as file:
        signature = file.read()

    isAuthentic = verify_signature_rsa(signature, image)
    print(isAuthentic)

    with open("image_2.png", "rb") as file:
        image2 = file.read()
    with open("image_2.sig", "rb") as file:
        signature2 = file.read()

    isAuthentic2 = verify_signature_rsa(signature2, image2)

    print(isAuthentic2)
```

U mom je slučaju image_1 autentična, dok image_2 nije.

```python
(abartu) C:\Users\A507\ab\vjezba3>digital_signatures.py
True
False
```