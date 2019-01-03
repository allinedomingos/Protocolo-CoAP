import opcao
import socket
from enum import Enum
import os, sys

# parametros de controle para transmissao de mensagens
# sao valores padrao

ACK_TIMEOUT = 2.0

ACK_RANDOM_FACTOR = 1.5

MAX_RETRANSMIT = 4

NSTART = 1

PORTA = 5683


class TipoMensagem(Enum):
    CON = b'\x00'  # confirmacao destino
    NON = b'\x10'  # nao confirmacao destino
    ACK = b'\x20'  # confirmacao de recebimento
    RST = b'\x30'  # mensagem recebida com erro

class Requisicao(Enum):
    EMPTY_MSG = b'\x00'
    GET = b'\x01'    # solicita ao webserver
    POST = b'\x02'   # cria um recurso no webserver.
    PUT = b'\x03'    # muda o estado de um recurso do webserver
    DELETE = b'\x04' # remove o recurso ou alterar para um estado vazio

class Confirmacao(Enum):
    CREATED =  b'\x41'
    DELETED =  b'\x42'
    VALID =  b'\x43'
    CHANGED =  b'\x44'
    CONTENT = b'\x45'

class Erro_Cliente(Enum):
    BAD_REQUEST =  b'\x80'
    UNAUTHORIZED = b'\x81'
    BAD_OPTION = b'\x82'
    FORBIDDEN =  b'\x83'
    NFOUND =  b'\x84'
    METHOD_NALLOW =  b'\x85'
    NACCEPTABLE =  b'\x86'
    PRECONDITION_FAILED =  b'\x8C'
    REQUEST_ENTITY_TLARGE =  b'\x8D'
    UNSUPPORTED_FORMAT =  b'\x8F'

class Erro_Servidor(Enum):
    INTERNAL_SERVER_ERR =  b'\xA0'
    NIMPLEMENT =  b'\xA1'
    BAD_GW =  b'\xA2'
    SERVICE_UNAVAILABLE =  b'\xA3'
    GW_TIMEOUT =  b'\xA4'
    PROXYING_NSUPPORTED =  b'\xA5'

class Delta(Enum):
    IF_MATC =  b'\x01'
    URI_HOST =  b'\x03'
    ETAG =  b'\x04'
    IF_NONE_MATCH =  b'\x05'
    URI_PORT =  b'\x07'
    LOCATION_PATH =  b'\x08'
    URI_PATH =  b'\x0B'
    CONTENT_FORMAT =  b'\x0C'
    MAX_AGE =  b'\x0E'
    URI_QUERY =  b'\x0F'
    ACCEPT =  b'\x11'
    LOCATION_QUERY =  b'\x14'
    PROXY_URI =  b'\x23'
    PROXY_SCHEME =  b'\x27'
    SIZE1 = B'\x3C'

class Coap:
	def __init__(self):
	    self.ver = b'\x40'
	    self.tipo = b'\x00'
	    self.token = b'\x00'
	    self.code = b'\x00'
	    self.IdMensagem = b'\x00'
	    self.delta = 0
	    self.tamanho = b'\x00'
	    self.opcoes = b'\x00'
	    self.payload = b'OlaMundo!'
	    self.quadro = b''
	    self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	    
	    
	def GeraIdMsg(self):
	    idM = os.urandom(2)
	    return idM
		
	def QuadroPayload(self):
	    self.quadro = b''
	    self.IdMensagem = self.GeraIdMsg()
	    self.quadro = (self.ver[0] | self.tipo[0] | self.token[0]).to_bytes(1, byteorder='big')
	    self.quadro += self.codigo + self.IdMensagem

	def Quadro(self):
	    self.quadro = b''
	    self.IdMensagem = self.GeraIdMsg()
	    self.quadro = (self.ver[0] | self.tipo[0] | self.token[0]).to_bytes(1, byteorder='big')
	    self.quadro += self.codigo + self.IdMensagem
	    
	def recpcao(self, quadro_recebido):
	    octave = quadro_recebido[0] 
	    quadro = quadro_recebido[1:]
	    ## Mascara para separar os bits
	    Ver = octave &192 # Versao do COAP - 11000000
	    T = octave & 48 # Tipo da mensagem - 00110000
	    TKL = octave & 15 # Tamanho Token - 00001111

	    if(T != 32): # ACK - 00100000
		    return (-1, None, None)
	    code = quadro_recebido[0]
	    quadro = quadro_recebido[1:]
	    
	    if (code >= 128 and code < 192):
		    return (1, code, None)
	    
	    if (code >= 64 and code <96):
		    MID = quadro_recebido[0:2]
		    quadro =quadro_recebido[2:]
		    if(MID != self.IdMensagem):
			    return (-2, None,None)
			    
		    quadro = quadro_recebido[TKL:]
		    valor = True
		    while valor:
			    opcao = quadro_recebido[0]
			    quadro = quadro_recebido[1:]
			    
			    op_delta = opcao & 240
			    op_length = opcao & 15
			    op_delta = op_delta >> 4

			    if (op_delta == 13):
				    op_delta = quadro_recebido[0]
				    quadro = quadro_recebido[1:]
			    if (op_delta == 14):
				    op_delta = quadro_recebido[0:2]
				    quadro = quadro_recebido[2:]
			    if (op_delta == 15):
				    if (op_length != 15):
					    return (-3, None, None)
				    else:
					    valor = False
				    payload = quadro

			    if (op_delta < 13):		
				    if (op_length == 13):
					    op_length = quadro_recebido[0]
					    quadro = quadro_recebido[1:]
				    if (op_length == 14):
					    op_length = quadro_recebido[0:2]
					    quadro = quadro_recebido[2:]
				    if (op_length == 15):
					    return (-3, None, None)
				    opcao2 = quadro_recebido[0:op_length]
		    return (1, codigo, payload)

	def Get(self, uri, host,op):
	    self.quadro = b''
	    self.host = host
	    self.tipo = TipoMensagem.CON.value
	    self.codigo = Requisicao.GET.value
	    self.op = op
	    
	    origem = (host, PORTA)
	    
	    #Monta quadro
	    self.Quadro()
	    
	    listaUri = uri.split('/')
	    for uri in  listaUri:
		    if int(self.op) == 11:
			    self.delta = Delta.URI_PATH.value[0] - self.delta
			    self.tamanho = len(uri)
			    self.opcoes = str.encode(uri)
			    self.quadro += (self.delta << 4 | self.tamanho).to_bytes(1, byteorder='big')
			    self.quadro += self.opcoes
		    elif int(self.op) == 3:
			    self.delta = Delta.URI_HOST.value[0] - self.delta
			    self.tamanho = len(uri)
			    self.opcoes = str.encode(uri)
			    self.quadro += (self.delta << 4 | self.tamanho).to_bytes(1, byteorder='big')
			    self.quadro += self.opcoes
		    else:
			    print('ERRO - Opção não encontrada')
	    
	    print('\n---------------------------\n')
	    print('Quadro: ' + str(self.quadro))
	    print('\n---------------------------\n')
	    
	    # Envia socket
	    self.sock.sendto(self.quadro, origem)
	    
	    # Aguarda resposta
	    mensagem , endereco = self.sock.recvfrom(1024)
	    print('Mensagem: ' + str(mensagem))
	    
	    resposta = self.recpcao(mensagem)
	    #print('Resposta' + str(resposta[2]))
	    
	def Post(self, uri, host):
		self.tipo = TipoMensagem.CON.value
		self.codigo = Requisicao.POST.value
		self.payload = self.payload
		self.host = host
		
		origem = (host, PORTA)
		
		# Montando quadro
	    
		self.QuadroPayload()
		for uri in  listaUri:
		    if int(self.op) == 11:
			    self.delta = Delta.URI_PATH.value[0] - self.delta
			    self.tamanho = len(uri)
			    self.opcoes = str.encode(uri)
			    self.quadro += (self.delta << 4 | self.tamanho).to_bytes(1, byteorder='big')
			    self.quadro += self.opcoes
		    elif int(self.op) == 3:
			    self.delta = Delta.URI_HOST.value[0] - self.delta
			    self.tamanho = len(uri)
			    self.opcoes = str.encode(uri)
			    self.quadro += (self.delta << 4 | self.tamanho).to_bytes(1, byteorder='big')
			    self.quadro += self.opcoes
		    else:
			    print('ERRO - Opção não encontrada')
	    
		print('\n---------------------------\n')
		print('Quadro: ' + str(self.quadro))
		print('\n---------------------------\n')
		
		# Envia socket
		self.sock.sendto(self.quadro, origem)
		
		# Aguarda resposta
		mensagem , endereco = self.sock.recvfrom(1024)
		print('Mensagem: ' + str(mensagem))
		
	def Put(self, uri, host):
	    self.tipo = TipoMensagem.CON.value
	    self.codigo = Requisicao.PUT.value
	    self.tamanho = len(uri)
	    self.opcoes = uri
	    self.delta = Delta.URI_PATH.value
	    self.payload = payload
	    self.host = host
	    
	    origem = (host, PORTA)
	    
	    # Montando quadro
	    
	    self.QuadroPayload()
	    
	    listaUri = uri.split('/')
	    for uri in  listaUri:
		    if int(self.op) == 11:
			    self.delta = Delta.URI_PATH.value[0] - self.delta
			    self.tamanho = len(uri)
			    self.opcoes = str.encode(uri)
			    self.quadro += (self.delta << 4 | self.tamanho).to_bytes(1, byteorder='big')
			    self.quadro += self.opcoes
		    elif int(self.op) == 3:
			    self.delta = Delta.URI_HOST.value[0] - self.delta
			    self.tamanho = len(uri)
			    self.opcoes = str.encode(uri)
			    self.quadro += (self.delta << 4 | self.tamanho).to_bytes(1, byteorder='big')
			    self.quadro += self.opcoes
		    else:
			    print('ERRO - Opção não encontrada')

	    print('\n---------------------------\n')
	    print('Quadro: ' + str(self.quadro))
	    print('\n---------------------------\n')
	    
	    # Envia socket
	    self.sock.sendto(self.quadro, origem)
	    
	    # Aguarda resposta
	    mensagem , endereco = self.sock.recvfrom(1024)
	    print('Mensagem: ' + str(mensagem))

	def Delete(self, uri, host):
	    self.tipo = TipoMensagem.CON.value
	    self.codigo = Requisicao.DELETE.value
	    self.tamanho = len(uri)
	    self.opcoes = uri
	    self.delta = Delta.URI_PATH.value
	    self.host = host
	    
	    origem = (host, PORTA)
	    
	    #Monta quadro
	    self.Quadro()
	    
	    listaUri = uri.split('/')
	    for uri in  listaUri:
		    if int(self.op) == 11:
			    self.delta = Delta.URI_PATH.value[0] - self.delta
			    self.tamanho = len(uri)
			    self.opcoes = str.encode(uri)
			    self.quadro += (self.delta << 4 | self.tamanho).to_bytes(1, byteorder='big')
			    self.quadro += self.opcoes
		    elif int(self.op) == 3:
			    self.delta = Delta.URI_HOST.value[0] - self.delta
			    self.tamanho = len(uri)
			    self.opcoes = str.encode(uri)
			    self.quadro += (self.delta << 4 | self.tamanho).to_bytes(1, byteorder='big')
			    self.quadro += self.opcoes
		    else:
			    print('ERRO - Opção não encontrada')
	    
	    print('\n---------------------------\n')
	    print('Quadro: ' + str(self.quadro))
	    print('\n---------------------------\n')
	    
	    # Envia socket
	    self.sock.sendto(self.quadro, origem)
	    
	    # Aguarda resposta
	    mensagem , endereco = self.sock.recvfrom(1024)
	    print('Mensagem: ' + str(mensagem))
