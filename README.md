# Security Log Analyzer

Analizador educativo de eventos de autenticación. Lee archivos locales, resume
la actividad y detecta patrones que requieren investigación. Funciona sin red,
sin credenciales y sin dependencias externas.

**Una alerta no demuestra un ataque. La ausencia de alertas tampoco demuestra seguridad.**

## Inicio rápido

Necesitas Python 3.10 o superior. Desde la carpeta del proyecto:

```bash
python3 analyzer.py examples/suspicious.jsonl
python3 analyzer.py examples/normal.jsonl
python3 -m unittest discover -s tests -v
```

El ejemplo sospechoso genera dos hallazgos: fallos repetidos por IP y un acceso
exitoso después de esos fallos para el mismo usuario e IP. Contiene 7 eventos:
5 fallos y 2 accesos exitosos. El ejemplo normal no supera el umbral predeterminado.
Todos los nombres y eventos son ficticios; las IP pertenecen a rangos de documentación.

## Formato de entrada

Se utiliza **JSON Lines**: un objeto JSON por línea, en UTF-8. No es una lista JSON.
Las líneas vacías se ignoran. Ejemplo de un evento:

```json
{"timestamp":"2026-01-15T10:00:00Z","ip":"192.0.2.10","user":"demo-admin","outcome":"failure"}
```

| Campo | Requisito |
| --- | --- |
| `timestamp` | Fecha y hora ISO 8601 con `T` y zona horaria; por ejemplo `Z` o `+02:00`. |
| `ip` | Dirección IPv4 o IPv6 válida. |
| `user` | Nombre de usuario como texto no vacío. |
| `outcome` | `failure` o `success`, en minúsculas. |

Los campos adicionales se ignoran. IP equivalentes y zonas horarias se normalizan.
Los usuarios se comparan exactamente, incluyendo mayúsculas. Las fechas se
presentan en UTC. Los eventos se ordenan por fecha; los empates mantienen el orden
original de las líneas. No se eliminan duplicados: cada línea cuenta como evento.

Los formatos SSH/syslog, Windows Event Log y CloudTrail **no se leen directamente**.
Deben convertirse primero a este esquema. Nunca incluyas contraseñas o tokens.

## Detecciones

### `REPEATED_FAILURES`

Al alcanzar el umbral de fallos desde una misma IP dentro de una ventana móvil,
se genera un hallazgo. Se agregan todos los usuarios de esa IP. El valor
predeterminado es **5 fallos en 10 minutos**; ambos límites de la ventana cuentan.

Solo se genera una alerta por episodio: no otra por cada fallo posterior mientras
el recuento se mantenga por encima del umbral. Cuando, al procesar otro evento de
esa IP, el recuento anterior baja del umbral, puede comenzar un nuevo episodio.
El recuento del hallazgo corresponde al instante de detección, no al total final.
Un acceso exitoso no borra el historial agregado de fallos de la IP.

### `SUCCESS_AFTER_FAILURES`

Un acceso exitoso después del umbral de fallos en la ventana para **la misma IP
y el mismo usuario** genera un hallazgo. Cualquier acceso exitoso reinicia el
historial de fallos de esa pareja IP/usuario, incluso si no genera una alerta.
No se correlacionan fallos de otros usuarios o de otras IP.

Una IP compartida, una contraseña olvidada o una integración mal configurada
pueden producir estos patrones. Investiga contexto antes de sacar conclusiones.

## Opciones y salida

```bash
# Cambiar sensibilidad
python3 analyzer.py examples/suspicious.jsonl --threshold 3 --window-minutes 5

# Informe estructurado
python3 analyzer.py examples/suspicious.jsonl --format json

# Para automatización: devolver 1 si hay hallazgos
python3 analyzer.py examples/suspicious.jsonl --fail-on-findings

# Guardar un informe (la carpeta reports está ignorada por Git)
mkdir -p reports
python3 analyzer.py examples/suspicious.jsonl --format json > reports/demo.json

python3 analyzer.py --help
```

El umbral mínimo es 2. La ventana acepta enteros de 1 a 10080 minutos (7 días).
Las rutas relativas se interpretan desde el directorio actual. No se modifican
los archivos de entrada. El formato JSON contiene `notice`, `settings`, `summary`
y `findings`; el resumen incluye fechas, recuentos y fallos por IP. Cada hallazgo
contiene código, IP, usuario (o `null` para la agregación por IP), fechas, número
de fallos y explicación.

| Código de salida | Significado |
| --- | --- |
| `0` | Análisis completado; puede haber hallazgos si no usaste `--fail-on-findings`. |
| `1` | Hay hallazgos y se indicó `--fail-on-findings`. |
| `2` | Argumentos inválidos, archivo vacío/inaccesible o datos inválidos. |

Los errores se envían a stderr sin informes parciales. Un archivo con una línea
inválida se rechaza por completo; no se omiten errores silenciosamente.

## Pruebas y estructura

```bash
python3 -m unittest discover -s tests -v
```

Las pruebas cubren ventanas temporales, límites inclusivos, normalización,
correlación, reinicios, alertas duplicadas, archivos inválidos y la CLI real.
GitHub Actions está configurado para ejecutar la suite en Python 3.10 y 3.12.
La configuración de CI no implica que se haya ejecutado en GitHub todavía.

```text
analyzer.py                  Análisis, validación e interfaz por terminal
examples/normal.jsonl         Actividad ficticia sin alertas predeterminadas
examples/suspicious.jsonl     Actividad ficticia con dos alertas
tests/test_analyzer.py       Pruebas unitarias y de CLI
docs/learning-notes.md       Decisiones y ejercicios de aprendizaje
```

## Límites y próximos pasos

Es una herramienta offline para archivos pequeños o medianos: carga y ordena
los eventos en memoria. No es un SIEM ni un detector en tiempo real. No detecta
ataques distribuidos entre IP, no consulta reputación, no bloquea direcciones y
no identifica por sí sola accesos comprometidos. Su calidad depende de la
integridad y cobertura de los registros y de las fechas del sistema de origen.

Posibles ampliaciones: adaptadores para SSH/syslog, reglas para múltiples IP y
exportación CSV. No forman parte de esta primera versión.

## Privacidad y aprendizaje

Usa registros ficticios para demostraciones públicas. `local-logs/` y `reports/`
están ignorados por Git para ayudar a separar archivos locales; revisa siempre
lo que vas a publicar. Los informes pueden contener usuarios e IP.

Proyecto desarrollado con asistencia de IA. Consulta las
[notas de aprendizaje](docs/learning-notes.md). Las contribuciones y conclusiones
personales deben registrarse por su autor; no se atribuyen ejercicios completados.

## Licencia

[MIT](LICENSE).
