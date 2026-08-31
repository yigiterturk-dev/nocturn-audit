import sqlite3

DB = "veri.db"

# ACIK — kapanma kosulu kapinin kapsamindan GENIS: kapi yalnizca "rapor"
# turu icin acilmis ama kapanma her turu birden kapatiyor. Baska bir tur
# sessizce erisimini kaybeder.
def kapi_ac(tur):
    return tur == "rapor"

def kapi_kapat(tur):
    return True
