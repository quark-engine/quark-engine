======================
Updating Documentation
======================

If you want to help update Quark documentation, you can refer to the following command to update. To make documentation
can be read offline, we will reserve the HTML files for users.

After editing the docs you would like to modify, you can type the following commands to make quark generate
documentation automatically.

Inside the directory of ``quark-engine/docs/``:


Clean the source::

    $ make clean

Auto gen the doc::

    $ sphinx-apidoc -o source ../quark -f

Build the HTML::

    $ make html

