## GuardianOS

Ce repository contient le code source du simulateur utilisé pour le project GuardianOS. 

### Installation
Pour utiliser le simulateur, il faut avoir une installation de Docker fonctionnelle (environ 10Go d'espace nécessaire).

#### QEMU
Après avoir cloné ce repository, il faut cloner QEMU, le patcher et le compiler. Pour cela, rendez-vous à la racine du repository et exécutez les commandes suivantes:

```bash
git clone git@github.com:qemu/qemu.git
cd qemu
git apply qemu_guardianos.patch
./configure --target-list=riscv64-softmmu
make -j$(nproc)
```


#### seL4

L'utilisation de Docker n'est pas obligatoire, mais fortement recommandée. Si vous souhaitez installer les dépendances pour seL4 sur votre machine, rendez-vous sur cette section de la documentation [seL4](https://docs.sel4.systems/projects/buildsystem/host-dependencies.html).

Pour récupérer le conteneur Docker ayant déjà toutes les dépendances installées, exécutez la commande suivante à la racine du repository:

```bash
docker run --rm -it \
    -v $(pwd):/host \
    -w /host \
    trustworthysystems/camkes
```

Une fois le conteneur lancé, il faut simplement lier le nouveau QEMU compilé pour qu'il soit utilisé par le simulateur. Pour cela, un petit script est fourni:

```bash
./setup_qemu.sh
```
Attention : Il faut lancer ce script à chaque fois que vous lancez le conteneur Docker.

### Utilisation

Pour une première utilisation, vous pouvez directement lancer le script suivant qui configure le build du project et lance le simulateur:

```bash
./launch.sh
```
Vous pouvez aussi réaliser les étapes manuellement.

Le code source du security_monitor se trouve dans le dossier projects/security_monitor. Le dossier de build du projet doit se trouver à la racine du repository (convention de seL4). Une fois le dossier de build créé, vous pouvez vous y rendre et lancer la commande suivante pour initialiser le build:

```bash
../security_monitor/init-build.sh -DPLATFORM=qemu-riscv-virt \
    -DCMAKE_C_FLAGS="-march=rv64imac -mabi=lp64" \
    -DSIMULATION=TRUE \
    -DOPENSBI_PATH="/host/tools/opensbi"
```

Ensuite, la compilation se fait en lançant la commande suivante dans ce même dossier:

```bash
ninja
```

Ensuite, le simulateur se lance avec la commande suivante:

```bash
./simulate --extra-qemu-args="-bios none -device security_oracle -device crypto_device -device my_ip"
```

Les IP's (devices PCI) sont ici explicitement déclarées (security_oracle, crypto_device, my_ip...)


#### Ajout d'IP dans le simulateur

Les sources pour les IP's sont dans le dossier `qemu/hw/misc`. Si vous ajoutez une nouvelle IP, il faut la déclarer dans le fichier `qemu/hw/misc/Kconfig` : 

```
config MY_ORACLE
    bool
    default y
    depends on PCI

config MY_IP_CRYPTO
    bool
    default y
    depends on PCI && MY_ORACLE

config MY_IP
    bool
    default y
    depends on PCI && MY_ORACLE && MY_IP_CRYPTO

... 
```
Et dans le fichier `qemu/hw/misc/meson.build` :

```
# GuardianOS Security Oracle
system_ss.add(when: 'CONFIG_MY_ORACLE', if_true: files('security_oracle.c'))

# GuardianOS IP's
system_ss.add(when: 'CONFIG_MY_IP_CRYPTO', if_true: files('my_ip_crypto.c'))
system_ss.add(when: 'CONFIG_MY_IP', if_true: files('my_ip.c'))
...
```