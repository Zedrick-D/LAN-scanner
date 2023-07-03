import socket
from scapy.all import ARP, Ether, srp
from manuf import manuf

ip_red = "192.168.1.0/24"

def obtener_marca(mac):
    m = manuf.MacParser()
    return m.get_manuf(mac)

def obtener_modelo(ip):
    try:
        nombre_host = socket.gethostbyaddr(ip)[0]
        return nombre_host.split('.')[0]
    except socket.herror:
        return "Desconocido"


def scanear_red(ip):
    arp = ARP(pdst=ip)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    paquete = ether/arp
    resultado = srp(paquete, timeout=3, verbose=0)[0]
    dispositivos = []
    for enviar, recibir in resultado:
        marca = obtener_marca(recibir.hwsrc)
        modelo = obtener_modelo(recibir.psrc)
        dispositivos.append({'IP': recibir.psrc, 'MAC': recibir.hwsrc, 'Marca': marca, 'Modelo': modelo})
    return dispositivos

def main():
    dispositivos_conectados = scanear_red(ip_red)

    for dispositivo in dispositivos_conectados:
        marca = dispositivo['Marca'] if dispositivo['Marca'] is not None else "Desconocida"
        modelo = dispositivo['Modelo'] if dispositivo['Modelo'] is not None else "Desconocido"
        print("IP: " + dispositivo['IP'] + "\tMAC: " + dispositivo['MAC'] + "\tMarca: " + marca + "\tModelo: " + modelo)

if __name__ == "__main__":
    main()