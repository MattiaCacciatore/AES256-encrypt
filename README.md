Made by Mattia Cacciatore <cacciatore1995@hotmail.it>

Computer science student at UniGe (University of Genoa - Italy) - Department DIBRIS - Computer science 

24 Feb 2021 - Genoa Italy

Version 1.0 - Written in C++

[ITA]
Questo programma è basato sull'implementazione del AES 256 basato sulla
documentazione ufficiale (vedere Federal Information Processing Standards 
Publication 197 - 26 Nov 2001).
Questa è una versione semplificata dell'algoritmo di criptazione basato sul 
modello di Rijndael e si compone della sola parte di criptazione a 256 bit.
L'inserimento del messaggio/testo/password avviene dal main prendendo l'input
da tastiera, mentre la chiave segreta va inserita nell'apposito spazio nel file
"AES256_encrypted_functions.cpp" nella sezione "Matrici e Array globali".
Venendo usati gli unsigned char ricordo che vanni inseriti nella forma '0x12', 
ed essi vanno da 0x00 a 0xff. 
La lunghezza del codice e alcune scelte implementative sono state sacrificate un
pochettino dal lato dell'efficienza a favore della leggibilità. Essendo
l'algoritmo leggero e poco pesante a livello di complessità spaziale mi son 
permesso di seguire questa scelta.

L'attuale versione conta un solo test eseguito su quello fornito dalla
documentazione ufficiale FIPS 197.

[ENG]
This program is an implementation of AES 256 based on official documents 
(see Federal Information Processing Standards Publication 197 - 26 Nov 2001).
This is a simplified version of encryption algorithm based on Rijndeal's model,
it only support 256 bit encryption part.
The message/plaintext/password is taken by terminal/keyboard, while 
private key/secret key/cipher key is taken from the section "Global matrix 
and array" in "AES256_encrypted_functions.cpp".
Since unsigned char are used, i'd remind you their form, like this one: '0x12',
they go from 0x00 to 0xff.
Code size and some implementation choices were made in order to make it more 
readable to the detriment of efficiency. Since this algorithm isn't expensive
in terms of time and space complexity i took the liberty of following the choice made.

The current version is only tested on official documentation provided by FIPS 197.
