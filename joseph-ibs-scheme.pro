TEMPLATE = app
CONFIG += console
CONFIG -= app_bundle
CONFIG -= qt

SOURCES += main.c \
    buffer.c \
    xmalloc.c \
    fatal.c \
    bufbn.c \
    misc.c \
    bufaux.c \
    log.c \
    joseph_ibs_scheme.c

include(deployment.pri)
qtcAddDeployment()

HEADERS += \
    buffer.h \
    xmalloc.h \
    misc.h \
    log.h \
    joseph_ibs_scheme.h



unix:!macx: LIBS += -L$$PWD/../../../Mydata/sourcecode/openssl-1.0.1j/ -lssl

INCLUDEPATH += $$PWD/../../../Mydata/sourcecode/openssl-1.0.1j
DEPENDPATH += $$PWD/../../../Mydata/sourcecode/openssl-1.0.1j

unix:!macx: PRE_TARGETDEPS += $$PWD/../../../Mydata/sourcecode/openssl-1.0.1j/libssl.a

unix:!macx: LIBS += -L$$PWD/../../../Mydata/sourcecode/openssl-1.0.1j/ -lcrypto

INCLUDEPATH += $$PWD/../../../Mydata/sourcecode/openssl-1.0.1j
DEPENDPATH += $$PWD/../../../Mydata/sourcecode/openssl-1.0.1j

unix:!macx: PRE_TARGETDEPS += $$PWD/../../../Mydata/sourcecode/openssl-1.0.1j/libcrypto.a


unix:!macx: LIBS += -ldl
