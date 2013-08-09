Make sure that you have the latest Bouncy Castle (from git) installed as a library dependency. In your local Bouncy 
Castle checkout do a `gradle :core:jar` and then install the resulting .jar from core/build/...

Also: make sure to edit the project settings and add the proper -Djava.net.ssl.KeyStore, etc. parameters so the server 
can find your certs.
