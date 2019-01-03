import coap
import os
import sys

#.well-known/core

print('Digite a Opção Desejada:')
print('\n---------------------------\n')
print('11- URI-PATH')
print('3- URI-HOST')
print('\n---------------------------\n')
opcao = input()

print('Informe a Uri')
uri = input()

print('Informa o Ip')
ip = input()

clienteCoap = coap.Coap()
uri_bytes = uri
clienteCoap.Get(uri_bytes,ip,opcao)
#clienteCoap.Put(uri_bytes,ip,opcao)
