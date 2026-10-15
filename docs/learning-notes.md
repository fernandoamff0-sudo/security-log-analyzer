# Notas de aprendizaje

## Decisiones implementadas

- JSON Lines permite representar un evento por línea sin depender de un proveedor.
  No se afirma compatibilidad directa con registros de sistemas específicos.
- Las fechas con zona horaria se convierten a UTC antes de ordenar y comparar.
  Sin zona, dos servidores podrían describir instantes diferentes con la misma hora.
- La ventana móvil incluye su límite inicial. Las pruebas cubren exactamente
  diez minutos y un evento que queda fuera de ese intervalo.
- Un diccionario de colas conserva fallos por IP y por pareja IP/usuario.
  Las entradas antiguas se descartan al volver a procesar esa clave.
- La regla por IP cuenta fallos entre distintos usuarios, pero la correlación
  con un acceso exitoso requiere el mismo usuario y la misma IP.
- El historial agregado por IP no se reinicia por un éxito; el historial de la
  pareja sí. Son reglas distintas y las pruebas reflejan esa diferencia.
- El texto cita los usuarios con escape JSON para que saltos de línea o secuencias
  de control presentes en registros no se interpreten como instrucciones de terminal.
- Se rechazan entradas inválidas por completo para evitar presentar un resumen
  parcial como si describiera todos los registros.

## Ejercicios sugeridos

1. Ejecuta los dos ejemplos y explica por qué solo uno genera alertas.
2. Cambia el umbral y observa cómo modifica los resultados.
3. Cambia la IP del acceso exitoso y explica por qué desaparece su correlación.
4. Investiga qué datos sensibles pueden aparecer en logs y cómo minimizarlos.
5. Diseña una prueba antes de añadir una nueva regla.

## Registro personal

Añade aquí tus cambios, referencias y conclusiones con tus propias palabras.
Estas notas fueron preparadas con asistencia de IA y no acreditan ejercicios
realizados ni experiencia profesional del propietario del repositorio.
