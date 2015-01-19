from distutils.core import setup
import py2exe

setup(console=['pipe.py'],options={
	'py2exe' : {
		'packages' : [ 'keyring.backends', 'lxml.etree', 'lxml._elementpath', 'gzip' ],
	}
})