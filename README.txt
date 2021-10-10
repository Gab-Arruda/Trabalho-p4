Formato do pacote:

Ethernet
IPv4
Int_pai
int_filho1
...
int_filhoN
TCP/ UDP


pensei em inserir o int entre o IP e o TCP. 
Definindo-se um protocol ID para o INT (arbitrei 150 (0x96)),
pode-se fazer o parser detectar a existencia pelo campo 
correspondente ao ip.protocol.


Tamanho atual do intFilho= 104 bits.


Tutorial de teste:
https://docs.google.com/document/d/1pk77sS_1S6r6ncPKz0G-BVlcWwKWCnyoxSvD0JW3Xu0/edit?usp=sharing

