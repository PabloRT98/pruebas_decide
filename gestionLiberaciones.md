# Gestión de liberaciones, despliegue y entregas

## Proceso definido para las liberaciones con un apartado explícito de cómo ha elegido la licencia de software para su proyecto

En cuanto al proceso definido para las liberaciones, estas siempre estarán enlazadas a una tag. Las tags hacen referencia a las distintas versiones del proyecto y están enlazadas con commits. Puede ver más información acerca de cómo administrar las liberaciones en **GitHub** [aquí](https://help.github.com/articles/creating-releases/). Si quiere obtener, de la misma forma, más información acerca del uso de las tags en **GitHub** puede consultar este [enlace](https://developer.github.com/v3/git/tags/).
Se puede ver un ejemplo de liberación (release) [aquí](https://github.com/decide-moltres/decide-votacion/releases/tag/v1.1).

La licencia elegida para el proyecto Decide-Moltres-Votacion es una licencia de tipo copyleft, en concreto la 
[AGPL 3.0](https://www.gnu.org/licenses/agpl-3.0.en.html). Esta licencia, entre otras cosas, especifica que el trabajo 
desarrollado a partir de código que esté bajo ella debe seguir teniendo la misma licencia. Por lo tanto, no podemos 
cambiarla ya que el proyecto parte de un fork de Decide que cuenta con una licencia de este tipo.

## Proceso definido para el despliegue
Para todo lo que conlleva el proceso de despliegue y la automatización de las pruebas correspondientes a nuestro proyecto hemos usado la herramienta Travis con el objetivo de probar y desplegar nuestro código. Para configurar dicha herramienta, primeramente, tenemos que sincronizar nuestro perfil de GitHub, que contiene todos los repositorios (públicos) y seleccionar aquel que contiene todo el código perteneciente a nuestro proyecto. Para realizar dicha comunicación debemos especificar un archivo .travis.yml en el directorio base de nuestro proyecto que contendrá los parámetros necesarios para que cada vez que realicemos un push a nuestro repositorio remoto, la herramienta Travis comience a desarrollar un nuevo build en el que se comienzan a correr los tests correspondientes al código perteneciente de dicho push.

Dicho esto, y suponiendo que los tests se hayan ejecutado correctamente y, por tanto, hayamos obtenido una salida satisfactoria, se procederá a realizar los tests proporcionados por la herramienta de cobertura Codacy. De manera similar a como hacíamos en Travis, iniciamos sesión con GitHub para visualizar los repositorios disponibles a los cuales podemos aplicar la cobertura de código y seleccionamos el correspondiente a nuestro proyecto. Para automatizar este proceso con Travis, debemos obtener una API Key de Codacy, especificarla como variable de entorno en la herramienta Travis y añadir una serie de parámetros al archivo .travis.yml de manera que se automatice dicho proceso.

Si el build ha llegado a realizarse sin ningún tipo de error, procederemos a la última fase: el despliegue en Heroku.
Para desplegar nuestra aplicación en este hosting, es obvio que debemos crearnos una cuenta en dicha página e instalar de igual forma Heroku CLI para especificar una serie de parámetros referentes a nuestro proyecto en el hosting, como, por ejemplo, el repositorio remoto que corresponderá a nuestro código. En otros archivos como settings.py, runtime.txt y Procfile se debe especificar la dirección URL de nuestro proyecto desplegado en Heroku, la versión de Python que se usará en el hosting y ficheros propios con una configuración determinada del hosting que nos ocupa respectivamente.

Nuevamente y como en los casos descritos anteriormente, se añaden una serie de parámetros al archivo .travis.yml de manera que cuando todos los tests sean ejecutados correctamente, la aplicación procederá a desplegarse en Heroku con el código perteneciente al último commit de nuestro repositorio remoto.

Para más información sobre los procesos, métodos y parámetros utilizados, puede consultar los siguientes enlaces: <br>
[Travis calidad del código](https://1984.lsi.us.es/wiki-egc/index.php/Travis_calidad_de_c%C3%B3digo) <br>
[Gestión del despliegue: Heroku y Vagrant](https://1984.lsi.us.es/wiki-egc/index.php/Gesti%C3%B3n_del_despliegue:_Heroku_y_Vagrant) <br>
[Gestión de incidencias y integración continua completa](https://1984.lsi.us.es/wiki-egc/index.php/Gesti%C3%B3n_de_incidencias_y_integraci%C3%B3n_continua_completa)

## Proceso definido para las entregas
En el caso de las entregas, los miembros del equipo deberán haber conformado una versión libre de fallos del proyecto, totalmente funcional o en su defecto, que la funcionalidad que implemente dicha versión a entregar actúe de la forma esperada.

Es de vital importancia seguir un proceso de verificación de manera que asegure que el producto cumple con los requisitos establecidos antes de ser entregado

Una vez que se ha revisado de forma exhaustiva que el proyecto se ejecuta y que funciona como debiera, será el Project Manager (junto con el resto del equipo) el que se encargue de verificar que la subida de todos los archivos correspondientes a nuestro trabajo se realiza de forma satisfactoria. Para la subida de archivos, utilizaremos la web de Opera proporcionada por la Universidad de Sevilla, como indicaremos debidamente en el siguiente apartado.


## Política de nombrado e identificación de los entregables

La codificación de los documentos del proyecto será la siguiente: 
**Decide-Moltres-Votacion-EGC-MN-G05.zip**

   * **N** = Número de Milestone
   * **G05** = Grupo de prácticas

Este archivo comprimido contendrá el repositorio correspondiente a todo lo relacionado con el desarrollo de la funcionalidad perteneciente a nuestro módulo (en nuestro caso, votación) y se subirá siguiendo el método indicado anteriormente en el apartado _Proceso definido para las entregas_ a la Web de Opera http://opera.eii.us.es/
