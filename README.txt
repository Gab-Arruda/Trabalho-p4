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

****ETAPA 2****:
Antes de encaminhar um pacote para o endhost, o switch deve extrair o header INT e enviar somente o pacote original, sem o INT.
Os headers INT devem ser enviados para um endhost específicado, responsável por apresentar as estatisticas da rede (telemetry analytics engine).
Dessa forma, ao verificar que o próximo hop é o host destino do pacote, o switch deve clonar o pacote, filtrar os INTs e encaminhar
corretamente os pacotes com e sem INTs.

Deve haver 2 programas receive. Um que mostra o pacote recebido por um endhost, da mesma forma que na etapa1, e outro que apresente
as informações do INT. 
Na aula sincrona do dia 27/10 foi dito que as informações de telemetria devem ser apresentadas de uma forma 
que não seja um simples print dos headers INT.

Sugestões dadas na apresentação da parte 1:
- (DONE) Criar defines
- usar registrador em vez de tabelas para o sw_ID
- (DONE) revisitar o esquema de usar stack headers
- (DONE) extrair um header por estado no parser
- colocar mais informações no INT_filho

Verificar se dá para usar h.minSizeInBytes() para evitar hardcoded
   -Aparentemente era para funcionar, mas a nossa versao nao suporta isso.


TODO list:
- criar uma flag no header INT_Pai indicando se o pacote está indo para o telemetry analytics engine.
    (Necessário para que não haja inserção de INT filhos nesses pacotes)
- colocar mais informações no INT_filho
    - tamanho da fila ?
    - numero de pacotes recebidos em cada porta ?
    - numero de pacotes enviados em cada porta ?
    - numero de pacotes dropados ?
- criar receive que mostre informações de forma interessante no telemetry analytics engine.
    - apresentar algo de forma gráfica seria legal.
- adicionar o endereço do telemetry analytics engine em todos os switches.
    (imagino ser semelhante à config ID dos switches)
- descobrir como funciona o clone.
- modificar parser para se adequar às alterações
- modificar ingress para se adequar às alterações
- modificar egress para se adequar às alterações
- ...

Tutorial de teste:
https://docs.google.com/document/d/1pk77sS_1S6r6ncPKz0G-BVlcWwKWCnyoxSvD0JW3Xu0/edit?usp=sharing

