# Informe SAST — TagLib 2.0.2

Revisión defensiva (Static Application Security Testing) de parsers de contenedor que consumen archivos multimedia no confiables.

**Alcance**

| Archivo | LOC |
|---|---|
| `taglib/ogg/oggpageheader.cpp` | 296 |
| `taglib/ogg/xiphcomment.cpp` | 522 |
| `taglib/asf/asffile.cpp` | 685 |
| `taglib/dsdiff/dsdifffile.cpp` | 926 |
| `taglib/it/itfile.cpp` | 321 |
| `taglib/s3m/s3mfile.cpp` | 244 |
| `taglib/mod/modfile.cpp` | 194 |

**Modelo de amenaza:** un archivo multimedia crafted abierto por un reproductor, indexador o editor de etiquetas que enlaza TagLib.

**Resumen:** 12 hallazgos (4 altos, 6 medios, 2 bajos). El riesgo dominante es denegación de servicio e integridad al guardar, no un overflow de heap clásico. `ByteVector::mid` recorta copias y `FileStream::readBlock` limita lecturas grandes al tamaño del archivo.

**Controles presentes:** `std::unique_ptr` para el estado privado, magics de formato (`OggS`, `FRM8`, `IMPM`, GUID ASF), `isValidChunkID` en DSDIFF, y `READ_ASSERT` en IT/S3M/MOD. El fallo recurrente es no acotar contadores y tamaños **después** de validar el magic.

`modfile.cpp` no tiene un hallazgo comparable: instrumentos fijos (15/31) y `save()` en offsets fijos.

Versiones posteriores de TagLib parchearon F-01 (#1424), F-02 (#1426) y F-03 (#1395).

---

## F-01 — Alto

- **Ubicación / Función:** `Ogg::XiphComment::parse` — `taglib/ogg/xiphcomment.cpp` líneas 428–521
- **Debilidad identificada:** `vendorLength`, `commentFields` y `commentLength` se toman del paquete sin comprobarlos contra los bytes restantes **antes** de avanzar `pos`. Un wrap unsigned de `pos` rebobina el parser y vuelve a copiar el mismo payload. Si `data.size() < 8`, `(data.size() - 8)` underflow y el tope de `commentFields` no sirve.
- **Clasificación estándar:** CWE-190 Integer Overflow / CWE-400 Uncontrolled Resource Consumption · OWASP A04:2021 Insecure Design
- **Riesgo e Impacto:** Paquete Vorbis/Opus/FLAC crafted → CPU/RAM en el proceso anfitrión. TagLib lo documentó después como #1424. `mid()` recorta, así que es DoS, no un heap overflow clásico.
- **Código Sugerido (Seguro):**

```cpp
static constexpr unsigned int MAX_XIPH_COMMENT_FIELD_COUNT = 50000;

if(data.size() < 8)
  return;

unsigned int pos = 0;
const unsigned int vendorLength = data.toUInt(0, false);
pos += 4;
if(vendorLength > data.size() - pos)
  return;

d->vendorID = String(data.mid(pos, vendorLength), String::UTF8);
pos += vendorLength;

if(data.size() - pos < 4)
  return;

const unsigned int commentFields = data.toUInt(pos, false);
pos += 4;
if(commentFields > MAX_XIPH_COMMENT_FIELD_COUNT ||
   commentFields > (data.size() - pos) / 4)
  return;

for(unsigned int i = 0; i < commentFields; i++) {
  if(data.size() - pos < 4)
    break;
  const unsigned int commentLength = data.toUInt(pos, false);
  pos += 4;
  if(commentLength > data.size() - pos)
    break;
  const ByteVector entry = data.mid(pos, commentLength);
  pos += commentLength;
  // ... parse entry ...
}
```

- **Recomendación de prevención:** Tratar cada longitud como no confiable. Comparar con el restante **antes** de sumar a `pos`. Fallar cerrado ante truncamiento. Poner tope a `commentFields`.

---

## F-02 — Alto

- **Ubicación / Función:** `HeaderExtensionObject::parse` — `taglib/asf/asffile.cpp` líneas 366–398
- **Debilidad identificada:** Se confía en `dataSize` anidado y se ignora el tamaño del objeto padre. Un hijo con `size == 0` es válido, `dataPos` no avanza y el bucle crea `UnknownObject` sin fin.
- **Clasificación estándar:** CWE-835 Infinite Loop / CWE-400 · OWASP A04:2021 Insecure Design
- **Riesgo e Impacto:** WMA/ASF crafted → hang + OOM. Parche posterior de TagLib (#1426): `childSize >= 24`, acotar `dataSize` al padre, máximo 50.000 objetos.
- **Código Sugerido (Seguro):**

```cpp
constexpr unsigned int MAX_ASF_HEADER_EXTENSION_OBJECT_COUNT = 50000;

void HeaderExtensionObject::parse(ASF::File *file, long long size)
{
  if(size < 46) {
    file->setValid(false);
    return;
  }
  file->seek(18, File::Current);
  bool ok = false;
  const long long dataSize = readDWORD(file, &ok);
  if(!ok || dataSize > size - 46) {
    file->setValid(false);
    return;
  }

  long long dataPos = 0;
  unsigned int objectCount = 0;
  while(dataPos < dataSize) {
    if(objectCount++ >= MAX_ASF_HEADER_EXTENSION_OBJECT_COUNT) {
      file->setValid(false);
      break;
    }
    const ByteVector uid = file->readBlock(16);
    const long long childSize = readQWORD(file, &ok);
    if(uid.size() != 16 || !ok || childSize < 24 || childSize > dataSize - dataPos) {
      file->setValid(false);
      break;
    }
    // parse child, then:
    dataPos += childSize;
  }
}
```

- **Recomendación de prevención:** Header hijo completo (24 bytes). Rechazar `size < 24`. Acotar datos anidados al padre. Tope de objetos. `setValid(false)` al primer hijo malformado.

---

## F-03 — Alto

- **Ubicación / Función:** `ASF::File::read` — `taglib/asf/asffile.cpp` líneas 625–678
- **Debilidad identificada:** `numObjects` es DWORD en un `int` sin tope. Cada iteración hace `new` de un objeto de header. No se exige `size >= 24`, así que objetos minúsculos inflan la lista.
- **Clasificación estándar:** CWE-400 / CWE-770 Allocation Without Limits · OWASP A04:2021 Insecure Design
- **Riesgo e Impacto:** Un header que declara millones de objetos pequeños fuerza asignaciones desproporcionadas al tamaño del fichero. TagLib #1395 rechaza conteos > 50.000.
- **Código Sugerido (Seguro):**

```cpp
static constexpr unsigned int MAX_ASF_HEADER_OBJECT_COUNT = 50000;

const unsigned int numObjects = readDWORD(this, &ok);
if(!ok || numObjects > MAX_ASF_HEADER_OBJECT_COUNT) {
  setValid(false);
  return;
}
for(unsigned int i = 0; i < numObjects; ++i) {
  auto size = readQWORD(this, &ok);
  if(!ok || size < 24) {
    setValid(false);
    break;
  }
  // ...
}
```

- **Recomendación de prevención:** Tope de objetos de header. `size >= 24` y `size <= restante`. Conteos en tipos unsigned. Abortar al primer objeto inválido.

---

## F-04 — Alto

- **Ubicación / Función:** `DSDIFF::File::read` — `taglib/dsdiff/dsdifffile.cpp` líneas 612–803
- **Debilidad identificada:** Tamaños leídos con `toLongLong` (signed) y guardados como `unsigned long long` en raíz. Un tamaño con bit alto se vuelve enorme. `tell() + chunkSize` puede wrapear y saltarse el check “mayor que el archivo”. En PROP/DST/DIIN el tamaño sigue signed: uno negativo pasa el test de cota superior y `seek(negativo, Current)` retrocede el parser.
- **Clasificación estándar:** CWE-190 / CWE-191 / CWE-20 · OWASP A04:2021 Insecure Design
- **Riesgo e Impacto:** DFF crafted evita bounds checks, recorre el fichero hacia atrás o finge chunks solapados. Un `save()` posterior con esos offsets puede corromper el archivo.
- **Código Sugerido (Seguro):**

```cpp
const unsigned long long chunkSize = readBlock(8).toULongLong(bigEndian);
const unsigned long long here = static_cast<unsigned long long>(tell());
const unsigned long long fileLen = static_cast<unsigned long long>(length());
if(chunkSize > fileLen - here) {  // resta, nunca suma
  setValid(false);
  break;
}
```

Para chunks internos, rechazar `dstChunkSize < 0` (o leer unsigned) antes de `seek`.

- **Recomendación de prevención:** Tamaños uint64. Comparar con resta (`remaining - size`), nunca con suma. Tope de número de chunks. No hacer `seek` con un size no validado.

---

## F-05 — Medio

- **Ubicación / Función:** `ASF::File::save` — `taglib/asf/asffile.cpp` línea 594
- **Debilidad identificada:** `insert(data, 30, static_cast<unsigned long>(d->headerSize - 30))` resta de un `headerSize` unsigned. Si el fichero reportó `headerSize < 30`, el `replace` hace underflow a un valor enorme. El cast a `unsigned long` además trunca en hosts 32-bit.
- **Clasificación estándar:** CWE-191 / CWE-681 · OWASP A08:2021 Software and Data Integrity Failures
- **Riesgo e Impacto:** Guardar tags sobre un ASF malformado puede reescribir mucho más que el header y destruir el medio.
- **Código Sugerido (Seguro):**

```cpp
if(!isValid() || d->headerSize <= 30)
  return false;

const size_t replace = static_cast<size_t>(d->headerSize - 30);
insert(data, 30, replace);
```

- **Recomendación de prevención:** No guardar si `!isValid()` o `headerSize <= 30`. Diferencia saturada. `offset_t`/`size_t` sin narrowing.

---

## F-06 — Medio

- **Ubicación / Función:** `ContentDescriptionObject::parse` — `taglib/asf/asffile.cpp` líneas 252–264
- **Debilidad identificada:** El parámetro `size` del objeto no se usa. Cinco longitudes WORD se confían y se leen strings sin presupuesto del objeto actual. El parser puede comer bytes del siguiente objeto de header.
- **Clasificación estándar:** CWE-130 / CWE-20 · OWASP A04:2021 Insecure Design
- **Riesgo e Impacto:** Un Content Description que declara 64 KiB de strings desincroniza el header. Junto con conteos sin tope, amplifica el DoS.
- **Código Sugerido (Seguro):**

```cpp
void parse(ASF::File *file, long long size) override
{
  const offset_t end = file->tell() + (size > 24 ? size - 24 : 0);
  auto boundedRead = [&](int len) -> String {
    if(len < 0 || file->tell() + len > end) {
      file->setValid(false);
      return String();
    }
    return readString(file, len);
  };
  const int titleLength = readWORD(file);
  file->d->tag->setTitle(boundedRead(titleLength));
  // igual para artist, copyright, comment, rating
}
```

- **Recomendación de prevención:** Offset de fin por objeto. Antes de cada lectura, `length <= remaining`. Invalidar el fichero si un campo cruza el límite del objeto.

---

## F-07 — Medio

- **Ubicación / Función:** `MetadataLibraryObject::parse` / `ASF::Attribute::parse` — `asffile.cpp` 338–345 (el `readBlock(size)` está en `asfattribute.cpp`)
- **Debilidad identificada:** El conteo de atributos es WORD (hasta 65.535). El size en Metadata Library es DWORD. `BytesType`/`GuidType`/`UnicodeType` llaman `readBlock(size)` sin tope por atributo más allá de la longitud del fichero.
- **Clasificación estándar:** CWE-770 · OWASP A04:2021 Insecure Design
- **Riesgo e Impacto:** Un atributo ASF puede meter el resto de un fichero grande en RAM como tag. Los indexadores que abren muchos ficheros en paralelo están más expuestos.
- **Código Sugerido (Seguro):**

```cpp
static constexpr unsigned int MAX_ASF_ATTRIBUTE_VALUE = 1024 * 1024;

if(size > MAX_ASF_ATTRIBUTE_VALUE) {
  debug("ASF::Attribute::parse() -- value exceeds cap");
  file.seek(size, File::Current); // o setValid(false)
  return name;
}
d->byteVectorValue = file.readBlock(size);
```

- **Recomendación de prevención:** Tope de conteo y de size por valor (p. ej. 1 MiB para fotos, mucho menos para texto). Verificar que cada atributo cabe en el objeto padre.

---

## F-08 — Medio

- **Ubicación / Función:** `IT::File::save` / `S3M::File::save` — `itfile.cpp` 101–183, `s3mfile.cpp` 127–141
- **Debilidad identificada:** Offsets de instrumentos/samples se toman del fichero y se usan como destino de `seek`/`write` sin rango contra `length()`. En IT, el mensaje se escribe en `messageOffset` tras una comparación unsigned que puede wrapear (`messageOffset + messageLength >= fileSize`).
- **Clasificación estándar:** CWE-20 / CWE-123 Write-what-where · OWASP A08:2021 Software and Data Integrity Failures
- **Riesgo e Impacto:** Cargar un IT/S3M crafted y guardar tags puede pisar sample data o extender el fichero en un offset elegido. Integridad local, no RCE remoto.
- **Código Sugerido (Seguro):**

```cpp
if(!readU32L(instrumentOffset))
  return false;
if(instrumentOffset < 4 ||
   instrumentOffset + 32 + 26 > static_cast<unsigned long>(length()))
  return false;

seek(instrumentOffset);
if(readBlock(4) != "IMPI")
  return false;
seek(instrumentOffset + 32);
writeString(i < lines.size() ? lines[i] : String(), 25);
```

- **Recomendación de prevención:** Validar cada offset: magic en el destino, `offset + field <= length()`, y que esté en la tabla esperada. No escribir si `!isValid()`. No escribir en `(offset + length)` wrapeado.

---

## F-09 — Medio

- **Ubicación / Función:** `IT::File::read` / `S3M::File::read` — `itfile.cpp` 199–315, `s3mfile.cpp` 158–240
- **Debilidad identificada:** `instrumentCount` / `sampleCount` (16-bit) son cotas de bucle sin tope. Un fichero truncado sigue el conteo declarado hasta que `READ_ASSERT` falla, con un seek+read por ítem.
- **Clasificación estándar:** CWE-400 · OWASP A04:2021 Insecure Design
- **Riesgo e Impacto:** Módulos con `count = 65535` fuerzan decenas de miles de seeks. Junto con offsets no confiables, es un DoS barato contra taggers por lote.
- **Código Sugerido (Seguro):**

```cpp
static constexpr unsigned short MAX_IT_INSTRUMENTS = 256;
static constexpr unsigned short MAX_IT_SAMPLES = 256;

READ_U16L_AS(instrumentCount);
READ_U16L_AS(sampleCount);
READ_ASSERT(instrumentCount <= MAX_IT_INSTRUMENTS);
READ_ASSERT(sampleCount <= MAX_IT_SAMPLES);
READ_ASSERT(192u + length + (instrumentCount + sampleCount) * 4u
            <= static_cast<unsigned>(length()));
```

- **Recomendación de prevención:** Tope realista de formato (IT: 256 samples es típico; 1024 es generoso). Exigir que la tabla de punteros quepa en el fichero antes de iterar. Fallar rápido al primer magic incorrecto.

---

## F-10 — Medio

- **Ubicación / Función:** `PageHeader::lacingValues` / `setPacketSizes` — `taglib/ogg/oggpageheader.cpp` líneas 75–78, 278–296
- **Debilidad identificada:** `packetSizes` es `List<int>`. `lacingValues()` hace `data.resize(data.size() + *it / 255)` sin comprobar que `*it` sea no negativo y acotado. Un size negativo se convierte en un `resize` enorme (unsigned).
- **Clasificación estándar:** CWE-190 / CWE-770 · OWASP A04:2021 Insecure Design
- **Riesgo e Impacto:** En lectura, los segmentos son 0–255 y los sizes quedan pequeños. El camino peligroso es el setter público más `render()`: un caller (o un parser que alimente `setPacketSizes`) puede forzar una asignación enorme. `Ogg::Page::packets()` también pasa esos `int` a `readBlock`.
- **Código Sugerido (Seguro):**

```cpp
ByteVector Ogg::PageHeader::lacingValues() const
{
  ByteVector data;
  for(int packetSize : d->packetSizes) {
    if(packetSize < 0 || packetSize > 255 * 255)
      return ByteVector();
    data.resize(data.size() + static_cast<unsigned>(packetSize) / 255, '\xff');
    if(/* not last incomplete packet */)
      data.append(static_cast<unsigned char>(packetSize % 255));
  }
  return data;
}
```

- **Recomendación de prevención:** Sizes unsigned. Rechazar negativos. Cap de payload por página (máx. Ogg: 255×255 bytes de datos + header). Comprobar overflow antes de `resize`.

---

## F-11 — Bajo

- **Ubicación / Función:** `DSDIFF::File::save` chunks DIIN DITI/DIAR — `dsdifffile.cpp` líneas 257–271
- **Debilidad identificada:** El prefijo de longitud usa `String::size()` (conteo de caracteres) pero el payload es `fromCString(toCString())` (Latin-1, cortado en NUL). Títulos Unicode producen una longitud que no coincide con los bytes; un NUL embebido trunca la escritura.
- **Clasificación estándar:** CWE-176 Improper Handling of Unicode Encoding / CWE-170 · OWASP A04:2021 Insecure Design
- **Riesgo e Impacto:** Tags DIIN guardados truncados o internamente inconsistentes. Integridad de datos / confusión del siguiente parser, no RCE.
- **Código Sugerido (Seguro):**

```cpp
const ByteVector titleBytes = diinTag->title().data(String::UTF8);
ByteVector diinTitle;
diinTitle.append(ByteVector::fromUInt(titleBytes.size(), d->endianness == BigEndian));
diinTitle.append(titleBytes);
setChildChunkData("DITI", diinTitle, DIINChunk);
```

- **Recomendación de prevención:** Serializar con encoding explícito (UTF-8 o Latin-1), luego `fromUInt(byteVector.size())` seguido de ese vector. No mezclar conteo de caracteres con longitudes de C-string.

---

## F-12 — Bajo

- **Ubicación / Función:** `pictureList` / `removePicture` / COVERART — `xiphcomment.cpp` líneas 350–368, 482–513
- **Debilidad identificada:** Las fotos son `FLAC::Picture*` crudos con `List` `autoDelete`. `pictureList()` devuelve una copia de esos punteros. COVERART se acepta sin tope de size decodificado. `removePicture(del=true)` hace `delete` aunque el puntero no estuviera en la lista.
- **Clasificación estándar:** CWE-416 Use After Free / CWE-770 · OWASP A04:2021 Insecure Design
- **Riesgo e Impacto:** Mal uso de API en el host (`delete` de un puntero de `pictureList()`, luego destruir el comment) es UAF. Un COVERART enorme duplica payload en memoria (base64 + decodificado). Crash del host, no RCE típico en un player bien aislado.
- **Código Sugerido (Seguro):**

```cpp
void Ogg::XiphComment::removePicture(FLAC::Picture *picture, bool del)
{
  auto it = d->pictureList.find(picture);
  if(it == d->pictureList.end())
    return;
  d->pictureList.erase(it);
  if(del)
    delete picture;
}

// En parse COVERART:
if(picturedata.size() > MAX_PICTURE_BYTES)
  continue;
```

- **Recomendación de prevención:** API con `unique_ptr` o vistas. Si `del` es true, borrar solo tras un `erase` exitoso. Tope de size de foto decodificada.

---

## Práctica transversal

En parsers de contenedor:

1. Validar longitudes contra bytes restantes con **resta**, nunca con suma.
2. Tope de contadores de objetos/campos.
3. Tamaño mínimo de header (p. ej. 24 bytes en ASF).
4. No guardar un fichero que no pasó `isValid()`.
5. No usar offsets del fichero como destino de escritura sin comprobar magic y rango.
