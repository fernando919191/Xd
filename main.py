from telegram import Update
from telegram.ext import (
    ApplicationBuilder,
    ContextTypes,
    MessageHandler,
    filters,
)
from dotenv import load_dotenv
from os import getenv
import random, re, requests, secrets, csv

# ─────────── CONFIG ───────────
load_dotenv()
TOKEN = getenv("BOT_TOKEN")
CANTIDAD_DEFECTO = 10
PAYPAL_CLIENT_ID = getenv("PAYPAL_CLIENT_ID")
PAYPAL_CLIENT_SECRET = getenv("PAYPAL_CLIENT_SECRET")
# ──────────────────────────────

# LIMPIEZA Y CONVERSIÓN
def normalizar_bin(bin_input: str) -> str:
    sin_sep = re.sub(r"[-/\s]", "", bin_input)
    return "".join(
        random.choice("0123456789") if ch.lower() in {"x", "c"} else ch
        for ch in sin_sep
    )

def fecha_aleatoria() -> tuple[str, str]:
    mes = f"{random.randint(1,12):02d}"
    anio = str(random.randint(2025, 2032))
    return mes, anio

def cvv_aleatorio() -> str:
    return "".join(random.choices("0123456789", k=3))

# API BINLIST.NET
def info_bin(bin_str):
    bin6 = ''.join([c for c in bin_str if c.isdigit()])[:6]
    if len(bin6) < 6:
        return "🔎 BIN inválido para consulta."
    try:
        r = requests.get(f"https://lookup.binlist.net/{bin6}", headers={"Accept-Version": "3"}, timeout=5)
        if r.status_code == 429:
            return info_bin_offline(bin6) + "\n🔁 Límite de consultas alcanzado, usando base offline."
        if r.status_code != 200:
            return info_bin_offline(bin6)
        data = r.json()
        banco = data.get("bank", {}).get("name", "Desconocido")
        pais = data.get("country", {}).get("name", "Desconocido")
        marca = data.get("scheme", "").capitalize()
        tipo = data.get("type", "").capitalize()
        # Guardar en offline si no existe
        try:
            existe = False
            with open("bins_offline.csv", encoding="utf-8") as f:
                for row in csv.DictReader(f):
                    if row["bin"] == bin6:
                        existe = True
                        break
            if not existe:
                with open("bins_offline.csv", "a", encoding="utf-8", newline='') as f:
                    writer = csv.writer(f)
                    writer.writerow([bin6, banco, pais, marca, tipo])
        except Exception:
            pass
        return f"🔎 BIN: {bin6}\n🏦 Banco: {banco}\n🌍 País: {pais}\n💳 Marca: {marca}, Tipo: {tipo}"
    except Exception:
        return info_bin_offline(bin6) + "\n🔁 Sin conexión, usando base offline."

def info_bin_offline(bin_str):
    bin6 = ''.join([c for c in bin_str if c.isdigit()])[:6]
    if len(bin6) < 6:
        return "🔎 BIN inválido para consulta (offline)."
    try:
        encontrado = False
        with open("bins_offline.csv", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                if row["bin"] == bin6:
                    encontrado = True
                    return (
                        f"🔎 BIN: {bin6}\n"
                        f"🏦 Banco: {row['banco']}\n"
                        f"🌍 País: {row['pais']}\n"
                        f"💳 Marca: {row['marca']}, Tipo: {row['tipo']}"
                    )
        # Si no se encontró, agregarlo con datos desconocidos
        if not encontrado:
            with open("bins_offline.csv", "a", encoding="utf-8", newline='') as f:
                writer = csv.writer(f)
                writer.writerow([bin6, "Desconocido", "Desconocido", "Desconocido", "Desconocido"])
        return f"🔎 BIN {bin6} no encontrado en base offline. Se ha agregado para futura referencia."
    except Exception as e:
        return f"🔎 Error leyendo base offline: {e}"

def luhn_checksum(card_number: str) -> int:
    def digits_of(n):
        return [int(d) for d in str(n)]
    digits = digits_of(card_number)
    odd_digits = digits[-1::-2]
    even_digits = digits[-2::-2]
    checksum = sum(odd_digits)
    for d in even_digits:
        checksum += sum(digits_of(d * 2))
    return checksum % 10

# GENERADOR DE TARJETAS FLEXIBLE
def generar_tarjeta(bin_raw: str, mes=None, anio=None, cvv=None) -> str:
    bin_norm = normalizar_bin(bin_raw)

    if not bin_norm.isdigit():
        return "❌ El BIN contiene caracteres no válidos."

    if len(bin_norm) < 6:
        return "❌ El BIN debe tener al menos 6 dígitos."

    # Detectar tipo de tarjeta por el primer dígito
    if bin_norm.startswith("3"):
        longitud_objetivo = 15  # American Express
        cvv_len = 4
    else:
        longitud_objetivo = 16  # Visa, MasterCard, Discover, etc.
        cvv_len = 3

    if len(bin_norm) > longitud_objetivo:
        return f"❌ El BIN excede los {longitud_objetivo} dígitos máximos permitidos para este tipo de tarjeta."

    num_faltantes = longitud_objetivo - 1 - len(bin_norm)
    cuerpo = bin_norm + "".join(random.choices("0123456789", k=num_faltantes))

    for i in range(10):
        posible = cuerpo + str(i)
        if luhn_checksum(posible) == 0:
            tarjeta_final = posible
            break
    else:
        return "❌ No se pudo generar una tarjeta válida."

    if anio and len(anio) == 2:
        anio = "20" + anio
    if not mes or not anio:
        mes, anio = fecha_aleatoria()
    if not cvv:
        cvv = "".join(random.choices("0123456789", k=cvv_len))

    return f"{tarjeta_final}|{mes}|{anio}|{cvv}"

def extrapolar_bin(bin_mask: str, mes=None, anio=None, cvv=None) -> str:
    # Reemplaza cada 'x' por un dígito aleatorio
    tarjeta_lista = [
        random.choice("0123456789") if ch.lower() == "x" else ch
        for ch in bin_mask
    ]
    # Calcula el dígito Luhn para la última posición
    if len(tarjeta_lista) in [15, 16]:
        cuerpo = tarjeta_lista[:-1]
        for i in range(10):
            posible = "".join(cuerpo) + str(i)
            if luhn_checksum(posible) == 0:
                tarjeta_lista[-1] = str(i)
                break
        tarjeta = "".join(tarjeta_lista)
    else:
        return "❌ La máscara debe tener 15 o 16 dígitos."

    # Detectar tipo de tarjeta para el CVV
    cvv_len = 4 if tarjeta.startswith("3") and len(tarjeta) == 15 else 3

    if anio and len(anio) == 2:
        anio = "20" + anio
    if not mes or not anio:
        mes, anio = fecha_aleatoria()
    if cvv == "rnd":
        pass
    elif not cvv:
        cvv = ""

    return f"{tarjeta}|{mes}|{anio}|{cvv if cvv is not None else ''}"

def validar_tarjeta(numero, mes, anio, cvv):
    if not numero.isdigit() or len(numero) not in [13, 15, 16]:
        return "❌ Número inválido."
    if luhn_checksum(numero) != 0:
        return "❌ No pasa Luhn."
    if not (mes.isdigit() and 1 <= int(mes) <= 12):
        return "❌ Mes inválido."
    if not (anio.isdigit() and len(anio) == 4 and 2024 <= int(anio) <= 2035):
        return "❌ Año inválido."
    if not (cvv.isdigit() and len(cvv) in [3, 4]):
        return "❌ CVV inválido."
    return "✅ Formato válido y pasa Luhn."

# HANDLERS
async def handler_gen(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user = update.effective_user
    if not usuario_autorizado(user.id, user.username):
        await update.message.reply_text("🔒 Debes activar tu licencia con `.activate TU-KEY`.")
        return

    texto = update.message.text.strip()
    if not texto.lower().startswith(".gen"):
        return

    resto = texto[4:].strip()
    tokens = [t for t in re.split(r"[|/\s]+", resto) if t]

    if not tokens:
        await update.message.reply_text(
            "⚠️ Usa `.gen BIN` o `.gen BIN|MM|AAAA|CVV` o `.gen BIN/MM/AAAA/CVV`\nEj: `.gen 5108xxxx|08|30|123` o `.gen 5108xxxx/08/30/123`",
            parse_mode="Markdown",
        )
        return

    bin_raw = tokens[0]
    mes = anio = cvv = None

    extras = tokens[1:]
    if extras:
        if '|' in extras[0] or '/' in extras[0]:
            sub = re.split(r"[|/]", extras[0])
            extras = sub + extras[1:]
        if len(extras) >= 1:
            mes = extras[0]
        if len(extras) >= 2:
            anio = extras[1]
        if len(extras) >= 3:
            cvv = extras[2]

    cantidad = CANTIDAD_DEFECTO
    if extras:
        posible_num = extras[-1]
        if posible_num.isdigit() and len(extras) > 3:
            cantidad = max(int(posible_num), CANTIDAD_DEFECTO)
            cvv = None if len(extras) == 4 else cvv

    tarjetas = [generar_tarjeta(bin_raw, mes, anio, cvv) for _ in range(cantidad)]
    bin_info = info_bin(normalizar_bin(bin_raw))
    encabezado = bin_info if bin_info else "🔎 No se encontró información del BIN."

    respuesta = encabezado + "\n\n" + "\n".join(f"`{t}`" for t in tarjetas)
    await update.message.reply_text(respuesta, parse_mode="Markdown")

async def handler_check(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user = update.effective_user
    if not usuario_autorizado(user.id, user.username):
        await update.message.reply_text("🔒 Debes activar tu licencia con `.activate TU-KEY`.")
        return

    texto = update.message.text.strip()
    if not texto.lower().startswith(".check"):
        return

    resto = texto[6:].strip()
    partes = [t for t in re.split(r"[|\s]+", resto) if t]
    if len(partes) < 4:
        await update.message.reply_text("⚠️ Usa `.check NUMERO|MM|AAAA|CVV`", parse_mode="Markdown")
        return

    numero, mes, anio, cvv = partes[:4]
    resultado = validar_tarjeta(numero, mes, anio, cvv)
    await update.message.reply_text(resultado, parse_mode="Markdown")

async def handler_registro(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user = update.effective_user
    registro = f"{user.id}|{user.username or 'sin_username'}|{user.first_name}\n"
    with open("usuarios.txt", "a", encoding="utf-8") as f:
        f.write(registro)
    await update.message.reply_text(
        f"✅ Registrado: {user.first_name} (@{user.username or 'sin_username'})"
    )

async def handler_start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    mensaje = (
        "👋 ¡Hola! Bienvenido al bot.\n\n"
        "Comandos disponibles:\n"
        "• `.gen BIN` — Genera tarjetas de prueba\n"
        "• `.check NUMERO|MM|AAAA|CVV` — Valida formato de tarjeta\n"
        "• `.reg` — Registra tu usuario\n"
        "• `.start` — Muestra este mensaje de ayuda\n"
    )
    await update.message.reply_text(mensaje, parse_mode="Markdown")

async def handler_extra(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    if not usuario_autorizado(user_id):
        await update.message.reply_text("🔒 Debes activar tu licencia con `.activate TU-KEY`.")
        return

    texto = update.message.text.strip()
    if not texto.lower().startswith(".extra"):
        return

    resto = texto[6:].strip()
    tokens = [t for t in re.split(r"[|/\s]+", resto) if t]
    if not tokens:
        await update.message.reply_text(
            "⚠️ Usa `.extra BINMASK|MM|AAAA|CVV` o `.extra BINMASK/MM/AAAA/CVV`",
            parse_mode="Markdown",
        )
        return

    bin_mask = tokens[0]
    mes = anio = cvv = None
    extras = tokens[1:]
    if extras:
        if '|' in extras[0] or '/' in extras[0]:
            sub = re.split(r"[|/]", extras[0])
            extras = sub + extras[1:]
        if len(extras) >= 1:
            mes = extras[0]
        if len(extras) >= 2:
            anio = extras[1]
        if len(extras) >= 3:
            cvv = extras[2]

    respuesta = ""
    # Si el usuario solo pone un BIN de 6-8 dígitos, genera 3 máscaras aleatorias
    if bin_mask.isdigit() and 6 <= len(bin_mask) <= 8:
        longitud = 15 if bin_mask.startswith("3") else 16
        for _ in range(3):
            mascara = generar_mascara_extrapolada(bin_mask[:6], longitud)
            tarjeta = extrapolar_bin(mascara, mes, anio, cvv)
            respuesta += f"Máscara: `{mascara}`\nTarjeta: `{tarjeta}`\n\n"
    else:
        # Si ya es una máscara, extrapola 3 veces
        for _ in range(3):
            tarjeta = extrapolar_bin(bin_mask, mes, anio, cvv)
            respuesta += f"Tarjeta: `{tarjeta}`\n"

    await update.message.reply_text(respuesta.strip(), parse_mode="Markdown")

def generar_mascara_extrapolada(bin6: str, longitud: int = 16) -> str:
    """
    Devuelve una máscara tipo BIN con los primeros 6 dígitos fijos y el resto
    mezcla de dígitos y 'x' en posiciones aleatorias, hasta completar la longitud.
    La última posición nunca será 'x', para permitir el cálculo Luhn.
    """
    restantes = longitud - len(bin6)
    mascara = []
    for i in range(restantes):
        # Última posición: nunca 'x'
        if i == restantes - 1:
            mascara.append(str(random.randint(0, 9)))
        else:
            mascara.append(random.choice(['x', str(random.randint(0, 9))]))
    random.shuffle(mascara[:-1])  # Mezcla todas menos la última
    return bin6 + ''.join(mascara)

async def handler_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    mensaje = (
        "📋 *Comandos disponibles:*\n"
        "• `.gen BIN` — Genera tarjetas de prueba\n"
        "• `.check NUMERO|MM|AAAA|CVV` — Valida formato de tarjeta\n"
        "• `.reg` — Registra tu usuario\n"
        "• `.start` — Muestra mensaje de bienvenida\n"
        "• `.extra BINMASK|MM|AAAA|CVV` — Extrapola tarjetas con máscara\n"
        "• `.cmd` — Muestra este listado de comandos\n"
    )
    await update.message.reply_text(mensaje, parse_mode="Markdown")

ADMIN_ID = 123456789  # Reemplaza con tu user_id de Telegram
ADMIN_USERNAME = "Yayo561"  # Sin @

async def handler_genkey(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user = update.effective_user
    if (user.username or "").lower() != ADMIN_USERNAME.lower():
        await update.message.reply_text("⛔ Solo el admin puede generar licencias.")
        return

    partes = update.message.text.strip().split()
    cantidad = 1
    if len(partes) > 1 and partes[1].isdigit():
        cantidad = int(partes[1])

    keys = []
    for _ in range(cantidad):
        key = secrets.token_hex(8).upper()
        keys.append(key)
        with open("licencias.txt", "a", encoding="utf-8") as f:
            f.write(f"{key}\n")

    await update.message.reply_text(
        "🔑 Licencias generadas:\n" + "\n".join(keys)
    )

async def handler_addbin(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user = update.effective_user
    if (user.username or "").lower() != ADMIN_USERNAME.lower():
        await update.message.reply_text("⛔ Solo el admin puede agregar BINs.")
        return

    texto = update.message.text.strip()
    partes = texto.split(maxsplit=5)
    if len(partes) < 6:
        await update.message.reply_text(
            "⚠️ Usa `.addbin BIN BANCO PAIS MARCA TIPO` (separado por espacios)\n"
            "Ejemplo: `.addbin 510805 Banamex Mexico Mastercard Debito`"
        )
        return

    _, bin6, banco, pais, marca, tipo = partes

    # Crear archivo si no existe
    import os
    archivo = "bins_offline.csv"
    existe = os.path.isfile(archivo)
    if not existe:
        with open(archivo, "w", encoding="utf-8", newline='') as f:
            writer = csv.writer(f)
            writer.writerow(["bin", "banco", "pais", "marca", "tipo"])

    # Revisar si ya existe el BIN
    ya_existe = False
    with open(archivo, encoding="utf-8") as f:
        for row in csv.DictReader(f):
            if row["bin"] == bin6:
                ya_existe = True
                break

    if ya_existe:
        await update.message.reply_text(f"⚠️ El BIN {bin6} ya existe en la base offline.")
        return

    # Guardar el nuevo BIN
    with open(archivo, "a", encoding="utf-8", newline='') as f:
        writer = csv.writer(f)
        writer.writerow([bin6, banco, pais, marca, tipo])

    await update.message.reply_text(f"✅ BIN {bin6} agregado correctamente a la base offline.")

async def handler_addcc(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user = update.effective_user
    if (user.username or "").lower() != ADMIN_USERNAME.lower():
        await update.message.reply_text("⛔ Solo el admin puede agregar BINs.")
        return

    texto = update.message.text

    import re, os
    archivo = "bins_offline.csv"
    existe = os.path.isfile(archivo)
    if not existe:
        with open(archivo, "w", encoding="utf-8", newline='') as f:
            writer = csv.writer(f)
            writer.writerow(["bin", "banco", "pais", "marca", "tipo"])

    # Divide el texto en bloques por líneas que contienen "CC:"
    bloques = re.split(r"(?:𝗖𝗖:|CC:|CC :)", texto)
    resultados = []
    for bloque in bloques:
        bloque = bloque.strip()
        if not bloque or not re.search(r"\d{6}\d{10,}\|", bloque):
            continue

        # Extraer la línea de tarjeta
        cc_line = re.search(r"(\d{6}\d{10,}\|[^\n]*)", bloque)
        if not cc_line:
            resultados.append("❌ No se encontró línea de tarjeta en un bloque.")
            continue

        # Extraer el BIN
        match = re.search(r'(\d{6})(\d{10,})\|', cc_line.group(1))
        if not match:
            resultados.append("❌ No se pudo extraer el BIN en un bloque.")
            continue
        bin6 = match.group(1)

        # Extraer datos de las líneas siguientes
        banco = pais = marca = tipo = "Desconocido"
        for line in bloque.splitlines():
            if "Country:" in line:
                pais = line.split("Country:")[1].strip().split(" ")[0]
            if "Bank:" in line:
                banco = line.split("Bank:")[1].strip()
            if "Type:" in line:
                tipo_marca = line.split("Type:")[1].strip().split(" - ")
                if len(tipo_marca) >= 2:
                    marca = tipo_marca[0].strip()
                    tipo = tipo_marca[1].strip()
                elif len(tipo_marca) == 1:
                    marca = tipo_marca[0].strip()

        # Revisar si ya existe el BIN
        ya_existe = False
        with open(archivo, encoding="utf-8") as f:
            for row in csv.DictReader(f):
                if row["bin"] == bin6:
                    ya_existe = True
                    break

        if ya_existe:
            resultados.append(f"⚠️ El BIN {bin6} ya existe.")
            continue

        # Guardar el nuevo BIN
        with open(archivo, "a", encoding="utf-8", newline='') as f:
            writer = csv.writer(f)
            writer.writerow([bin6, banco, pais, marca, tipo])
        resultados.append(f"✅ BIN {bin6} agregado.")

    await update.message.reply_text("\n".join(resultados))

def usuario_autorizado(user_id, username=None):
    # Permite siempre al admin por username
    if (username or "").lower() == ADMIN_USERNAME.lower():
        return True
    try:
        with open("usuarios_autorizados.txt", "r", encoding="utf-8") as f:
            return str(user_id) in [line.strip() for line in f]
    except FileNotFoundError:
        return False

def key_valida(key):
    try:
        with open("licencias.txt", "r", encoding="utf-8") as f:
            return key.strip() in [line.strip() for line in f]
    except FileNotFoundError:
        return False

def registrar_usuario(user_id, key):
    with open("usuarios_autorizados.txt", "a", encoding="utf-8") as f:
        f.write(f"{user_id}\n")
    # Elimina la key usada
    with open("licencias.txt", "r", encoding="utf-8") as f:
        keys = [line.strip() for line in f if line.strip() != key.strip()]
    with open("licencias.txt", "w", encoding="utf-8") as f:
        for k in keys:
            f.write(f"{k}\n")

async def handler_activate(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user = update.effective_user
    texto = update.message.text.strip()
    partes = texto.split()
    if len(partes) < 2:
        await update.message.reply_text("🔑 Usa `.activate TU-KEY` para activar tu acceso.")
        return
    key = partes[1]
    if usuario_autorizado(user.id, user.username):
        await update.message.reply_text("✅ Ya tienes acceso autorizado.")
        return
    if key_valida(key):
        registrar_usuario(user.id, key)
        await update.message.reply_text("✅ Licencia activada. Ahora puedes usar el bot.")
    else:
        await update.message.reply_text("❌ Licencia inválida o ya usada.")

# INICIO DEL BOT
if __name__ == "__main__":
    print("🟡 Iniciando bot...")
    if not TOKEN:
        print("❌ BOT_TOKEN no cargado desde .env")
        exit()

    app = ApplicationBuilder().token(TOKEN).build()
    app.add_handler(MessageHandler(filters.TEXT & filters.Regex(r"^\.gen"), handler_gen))
    app.add_handler(MessageHandler(filters.TEXT & filters.Regex(r"^\.check"), handler_check))
    app.add_handler(MessageHandler(filters.TEXT & filters.Regex(r"^\.reg"), handler_registro))
    app.add_handler(MessageHandler(filters.TEXT & filters.Regex(r"^\.start"), handler_start))
    app.add_handler(MessageHandler(filters.TEXT & filters.Regex(r"^\.extra"), handler_extra))
    app.add_handler(MessageHandler(filters.TEXT & filters.Regex(r"^\.cmd"), handler_cmd))
    app.add_handler(MessageHandler(filters.TEXT & filters.Regex(r"^\.key"), handler_genkey))
    app.add_handler(MessageHandler(filters.TEXT & filters.Regex(r"^\.activate"), handler_activate))
    app.add_handler(MessageHandler(filters.TEXT & filters.Regex(r"^\.addbin"), handler_addbin))
    app.add_handler(MessageHandler(filters.TEXT & filters.Regex(r"^\.addcc"), handler_addcc))

    async def error_handler(update: object, context: ContextTypes.DEFAULT_TYPE):
        print(f"⚠️ Error: {context.error}")
    app.add_error_handler(error_handler)

    print("✅ Bot corriendo… envía `.gen BIN`, `.check NUMERO|MM|AAAA|CVV`, `.reg` o `.start` en Telegram.")
    app.run_polling()
