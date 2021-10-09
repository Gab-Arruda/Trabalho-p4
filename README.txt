Formato do pacote:

Ethernet
IPv4
Int_pai
int_filho1
...
int_filhoN
TCP/ UDP


pensei em inserir o int entre o IP e o TCP. 
Definindo-se um protocol ID para o INT (arbitrei 0x66),
pode-se fazer o parser detectar a existencia pelo campo 
correspondente ao ip.protocol.

Duvidas:
Verificar a forma correta de inserir headers no pacote.
Descobrir como fazer o parser de multiplos int_filho.
