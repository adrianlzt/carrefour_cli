#!/usr/bin/env python

import sys
import requests
import os
import json
from mi_secrets import LOGIN,PASSWORD
from urllib.parse import urljoin

try:
    import click
except ImportError:
    print("click module has to be installed")
    sys.exit(1)

import logging

FORMAT = "[%(levelname)s %(filename)s:%(lineno)s - %(funcName)20s() ] %(message)s"
logging.basicConfig(level=logging.ERROR, format=FORMAT)
logger = logging.getLogger(__name__)

CACHE_FILE = "/var/tmp/carrefour.cache"

class Carrefour(object):
    def __init__(self, user, password, proxy=None):
        self.user = LOGIN
        self.password = PASSWORD

        self.endpoint = "https://courses.carrefour.fr"
        self.token = None

        self.proxies = {
                'http': proxy,
                'https': proxy
        }

        self.verify = False if proxy else True

    def _query(self, service, params=None, post=None, expected=200, estante=False):
        headers = {"Accept": "application/json"}
        if self.token and not estante:
            headers.update({"Token": self.token})

        url = urljoin(self.endpoint, service)
        if estante:
            url = service

        if post:
            r = requests.post(url, proxies=self.proxies, verify=self.verify, headers=headers, params=params, json=post)
        else:
            r = requests.get(url, proxies=self.proxies, verify=self.verify, headers=headers, params=params)

        if not r.ok:
            raise Exception(f"Error realizando query a {url}: {r.content}")

        if r.status_code != expected:
            raise Exception(f"Esperado status_code {expected} pero recibido {r.status_code}")

        return r.json()

    def _get_local_login(self):
        if not os.path.isfile(CACHE_FILE):
            return None

        with open(CACHE_FILE, "r") as fd:
            data = json.load(fd)

        # TODO: comprobar la fecha del validUntil a ver si sigue siendo valida

        return data

    def _save_local_login(self, token, userId, valid):
        with open(CACHE_FILE, "w") as fd:
            fd.write(json.dumps({
                "token": token,
                "userId": userId,
                "validUntil": valid
            }))

    def login(self):
        logger.debug("Haciendo login")

        login_cache = self._get_local_login()
        if login_cache:
            logger.info("Usando info de login almacenada en cache")
            self.token = login_cache["token"]
            self.userId = login_cache["userId"]
            return

        url = "service/token/generate"
        user_data = {"login": self.user, "password": self.password}
        resp = self._query(url, post=user_data)

        # Token valido 24h
        self.token = resp["accessToken"]
        self.userId = resp["userId"]
        validUntil = resp["validUntil"]
        self._save_local_login(self.token, self.userId, validUntil)
        logger.info(f"Login correcto. token {self.token}")

    def getUser(self):
        logger.debug("Obteniendo info del user")
        url = f"/service/user/{self.userId}"
        resp = self._query(url)
        self.tienda = resp["visitedDrives"]
        # TODO: almacenar esto tambien en el cache y no hacer getUser al comienzo

    def getSlots(self):
        """Slots disponibles para ir a recoger la compra"""
        url = f"/service/slot"
        params = {"storeRef": self.tienda, "service": "PICKING_DRIVE"}
        resp = self._query(url, params=params)

    def getBasket(self):
        """Obtener cesta de la compra actual"""
        url = f"/service/basket"
        params = {
                "customerRef": self.userId,
                "storeRef": self.tienda,
                "service": "PICKING_DRIVE",
                "displayUnavailableProds": "false"
        }
        resp = self._query(url, params=params)

        self.basketRef = resp["ref"]

        return resp

    def getShoppingList(self):
        """Listas de la compra predefinidas"""
        url = f"/service/shoppingList/unique"
        params = {
                "customerRef": self.userId,
                "storeRef": self.tienda
        }
        resp = self._query(url, params=params)

        return resp

    def getEstante(self, numero="R01F01"):
        """Obtiene los elementos de un estante segun su id"""
        url = f"https://cvg.cmm.prd.carrefour.fr/convertigo/projects/CommonModule/.json"
        params = {
                "__sequence": "GetProductsForNodeByPage",
                "appName": "drive",
                "num_rayon": numero,
                "client_id": None,
                "storeRef": self.tienda,
                "service": "PICKING_DRIVE",
                "offerFilter": "false",
                "page": 1,
                "slot_id": None
                }
        resp = self._query(url, params=params)

    def addItem(self, producto, cantidad=1):
        """
        Añadimos productos a la cesta de la compra.
        Si algún producto ya lo teníamos, actualizará la cantidad
        """
        logger.debug("Añadiendo productos")

        url = f"/service/basket/minibasket/{self.basketRef}/products"
        data = {
                "products":[
                    {"product_ref": producto, "qty": cantidad}
                ],
                "transactionNumber":"0"
        }
        resp = self._query(url, post=data)
        return resp


class Context(object):
    """Objecto para pasar informacion a los subcomandos"""
    def __init__(self):
        pass

pass_context = click.make_pass_decorator(Context, ensure=True)

@click.group()
@click.option('-v','--verbose', count=True, help="Repetir para mas verbosidad")
@click.option('-p','--proxy', help="Lanzar CLI a traves de un proxy")
@pass_context
def main(c, verbose, proxy):
    # set logging
    if verbose > 1:
        logger.setLevel(logging.DEBUG)
    elif verbose > 0:
        logger.setLevel(logging.INFO)

    # pasamos informacion
    carrefour = Carrefour("dummy", "dummy", proxy)
    c.carrefour = carrefour
    carrefour.login()
    carrefour.getUser()
    carrefour.getBasket()

@main.command()
@pass_context
def cesta(c):
    """Ver la cesta"""
    logger.info(f"Obtener cesta de la compra")

    cesta = c.carrefour.getBasket()
    click.echo("Cesta:")
    for item in cesta.get("items"):
        click.echo(item.get("productSimpleView").get("brandName"))

@main.command()
@pass_context
def listas(c):
    """Ver la listas predefinidas"""
    listas = c.carrefour.getShoppingList()
    click.echo(listas)

@main.command()
@click.argument('producto', nargs=1)
@click.option('--cantidad', default=1,
        help="Cuantas elementos queremos añadir")
@pass_context
def add(c, producto, cantidad):
    """Añadir un producto a la cesta"""
    logger.info(f"Añadiendo producto {producto} {cantidad} veces a la cesta")

    r = c.carrefour.addItem(producto, cantidad)
    click.echo(r)


# Parte necesaria si no es un package de python
# Si es un package tambien podremos quitar en shebang
if __name__ == '__main__':
    main()
    sys.exit(0)

