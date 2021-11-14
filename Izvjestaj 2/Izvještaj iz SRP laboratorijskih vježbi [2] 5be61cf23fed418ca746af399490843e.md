# Izvještaj iz SRP laboratorijskih vježbi [2]

# Symmetric key cryptography - a crypto challenge

## Uvod

---

### Fernet

Za ovu vježbu koristit ćemo [Fernet](https://cryptography.io/en/latest/fernet/), implementaciju simetrične enkripcije. Pomoću navedene klase omogućeno nam je kriptiranje kao i dekriptiranje poruka.

Fernet koristi navedene kriptografske mehanizme:

- AES šifru sa 128 bitnim ključem
- CBC enkripcijski način rada
- HMAC sa 256 bitnim ključem za zaštitu integriteta poruka
- Timestamp za osiguravanje svježine (*freshness*) poruka

---

## Upoznavanje s Fernetom

Pokretanje Python virtual environmenta:

```bash
python -m venv abartu
```

Instalacija potrebnog libraryja u virtualnom okruženju:

```bash
pip install cryptography
```

Importanje Fernet iz cryptography biblioteke:

```bash
from cryptography.fernet import Fernet
```

Funkcija *generate_key* generira novi Fernet ključ key. Ovaj ključ trebamo čuvati, jer bilo tko tko zna naš ključ može dekriptirati sve naše podatke, kao i stvarati lažne koristeći ga:

```bash
>>> key = Fernet.generate_key()

>>> key

b'dmiK8pm9AW_NBmXDWAKReCCGRzHlZrcKl43pe5wPQbg='
```

Instanciramo Fernet objekt f na temelju ključa key:

```bash
f = Fernet(key)
```

Enkriptiramo poruku pomoću ključa i spremamo u varijablu *ciphertext*:

```bash
>>> ciphertext = f.encrypt(b"hello world")

>>> ciphertext

b'gAAAAABhdpZ8nQrUOFUczfVtqE99fexaVn_waFN-qCGrFXdQ9O8I8w3YoZAu4Tz8_WDghLcgMMWErwGFvzXpyVZf7oAXfbB0WA=='
```

Pošto je f pridružen odgovarajući ključ, možemo dekriptirati ciphertext natrag u originalnu poruku koristeći metodu *decrypt*:

```bash
>>> f.decrypt(ciphertext)

b'hello world'

```

Za izlazak iz Python Shella koristimo sljedeću naredbu:

```bash
>>> exit()
```

## Pronalaženje odgovarajuće datoteke za izazov

`code my_challenge.py` stvara novu datoteku i otvara je u VS Code, gdje radimo kod za otkrivanje odgovarajućeg hasha:

```python
from cryptography.hazmat.primitives import hashes

def hash(input):
    if not isinstance(input, bytes):
        input = input.encode()

    digest = hashes.Hash(hashes.SHA256())
    digest.update(input)
    hash = digest.finalize()

    return hash.hex()

if __name__=="__main__":
    h = hash('bartulovic_antonia')
    print(h)
```

Pokretanje programa daje sljedeći izlaz:

```bash
(abartu) C:\Users\A507\ab>python my_challenge.py

37dc8e7b9728166c70861cc0985086d8c3be6d65999853b7f291599b51fc6a95
```

## Testiranje neispravnog ključa

U ovom dijelu izazova testirali smo Fernetovu sposobnost zaštite od dekriptiranja krivim ključem. Prvo instanciramo objekt f na temelju nekog kljuca key te njime enkriptiramo poruku, koju spremamo u varijablu *cipher*.

```bash
>>> from cryptography.fernet import Fernet

>>> key = Fernet.generate_key()

>>> f = Fernet(key)

>>> f.encrypt(b"hello")

b'gAAAAABhdp3M973qVW9OUlE6hbpegAMQTkZ3GnolKz_5avKpjYkxL8jiJv-aEUE-sy_1udYbcw-bd4ZQVtHbn-8wv5AFhCuxvQ=='

>>> cipher = f.encrypt(b"hello")

>>> cipher

b'gAAAAABhdp3c3RLl33V4YIiKDu8iSFzPld6HmGpuTcZsli0tHJgmMeti_uHAISgDYvkD20FOLnAaH9g2gNvRR_eOkOYYGzyIYA=='
```

Sada instanciramo *novi* objekt f na temelju novog ključa key i testiramo kako će Fernet reagirati na pokušaj dekripcije krivim ključem.

```bash
>>> key = Fernet.generate_key()

>>> f.decrypt(cipher)

Traceback (most recent call last):
  File "C:\Users\A507\ab\abartu\lib\site-packages\cryptography\fernet.py", line 124, in _verify_signature
    h.verify(data[-32:])
  File "C:\Users\A507\ab\abartu\lib\site-packages\cryptography\hazmat\primitives\hmac.py", line 78, in verify
    ctx.verify(signature)
  File "C:\Users\A507\ab\abartu\lib\site-packages\cryptography\hazmat\backends\openssl\hmac.py", line 76, in verify
    raise InvalidSignature("Signature did not match digest.")

cryptography.exceptions.InvalidSignature: Signature did not match digest.

During handling of the above exception, another exception occurred:

Traceback (most recent call last):
  File "<stdin>", line 1, in <module>
  File "C:\Users\A507\ab\abartu\lib\site-packages\cryptography\fernet.py", line 85, in decrypt
    return self._decrypt_data(data, timestamp, time_info)
  File "C:\Users\A507\ab\abartu\lib\site-packages\cryptography\fernet.py", line 142, in _decrypt_data
    self._verify_signature(data)
  File "C:\Users\A507\ab\abartu\lib\site-packages\cryptography\fernet.py", line 126, in _verify_signature
    raise InvalidToken
cryptography.fernet.InvalidToken
```

## Pseudokod za brute force napad i otkrivanje ključa (kao i poruke)

Ključ koji trebamo otkriti za "crackanje" koda zauzima samo 20 (22) bita, što se da brute force-ati u manje od nekoliko minuta.

Slijedi pseudokod funkcije za brute force implementiran u Pythonu:

```python
import base64
from cryptography.fernet import Fernet

def brute_force():

		# Input filename
		# Read from file into ciphertext variable

		# Set ctr variable to 0
		ctr = 0

		while True:
				# Loop while, break upon fuliflling condition
				# Create key variable based on ctr variable
				# Knowing Fernet throws an exception when an incorrect key is inputted,
				# make a try statement and pass on the except statement
				# Inside the try block, attempt to decrypt ciphertext and look for
				# patterns at the start of the plaintext (ie. extensions)
				# At the end of the loop, increment ctr variable

    # Reading from a file
    filename = "37dc8e7b9728166c70861cc0985086d8c3be6d65999853b7f291599b51fc6a95.encrypted"
    with open(filename, "rb") as file:
        ciphertext = file.read()

    while True:
        key_bytes = ctr.to_bytes(32, "big")
        key = base64.urlsafe_b64encode(key_bytes)

        try:
            f = Fernet(key)
            plaintext = f.decrypt(ciphertext)
            print(key, plaintext)
            break

        except Exception:
            pass

        ctr += 1

if __name__=="__main__":
    brute_force()
```

## Potpuni brute-force kod

```python
import base64
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet

def hash(input):
    if not isinstance(input, bytes):
        input = input.encode()

    digest = hashes.Hash(hashes.SHA256())
    digest.update(input)
    hash = digest.finalize()

    return hash.hex()

def test_png(header):
    if header.startswith(b"\211PNG\r\n\032\n"):
        return True

def brute_force():
    filename = "3f7699d1bc4ee53a3e8f24bfd2577a150260f938f45b8d6a538819129263bd13.encrypted"
    # Reading from a file
    with open(filename, "rb") as file:
        ciphertext = file.read()

    ctr = 0
    while True:
        key_bytes = ctr.to_bytes(32, "big")
        key = base64.urlsafe_b64encode(key_bytes)

        if not (ctr + 1) % 1000:
            print(f"[*] Keys tested: {ctr + 1:,}", end="\r")

        try:    
            plaintext = Fernet(key).decrypt(ciphertext)
            
            header = plaintext[:32]
            if test_png(header):
                print(f"[+] KEY FOUND: {key}")
                # Writing to a file
                with open("BINGO.png", "wb") as file:
                    file.write(plaintext)         
                break

        except Exception:
            pass
            
        ctr += 1

if __name__ == "__main__":
    # hash_value = hash("cagalj_mario")
    # print(hash_value)
    brute_force()
```

Izvršavanje koda daje nam rješenje:

```bash
(abartu) C:\Users\A507\ab\vjezba2\abartu\Scripts>python brute_force.py
[+] KEY FOUND: b'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACCXk='
```

Također dobijemo i sljedeću sliku, dokaz našeg uspješnog "hakiranja" 🙂

![Untitled](Izvjes%CC%8Ctaj%20iz%20SRP%20laboratorijskih%20vjez%CC%8Cbi%20%5B2%5D%205be61cf23fed418ca746af399490843e/Untitled.png)