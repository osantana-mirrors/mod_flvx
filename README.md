mod_flvx
========

FLV Progressive download streaming for Apache 2
-----------------------------------------------

Usage:

1. Compile and install with [apxs](http://httpd.apache.org/docs/2.0/programs/apxs.html) tool:

        apxs -c -i ./mod_flvx.c

2. Add the following lines to your httpd.conf or create a
   dedicated `/etc/httpd/conf.d/mod_flvx.conf` config file:

        LoadModule flvx_module modules/mod_flvx.so
        AddHandler flv-stream .flv

3. Restart Apache!
4. Now your flv files can be streamed using ?start= parameter

