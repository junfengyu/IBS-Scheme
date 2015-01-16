TEMPLATE = app
CONFIG += console
CONFIG -= app_bundle
CONFIG -= qt

SOURCES += main.c \
    schnorr.c \
    log.c \
    buffer.c \
    xmalloc.c \
    fatal.c \
    cleanup.c \
    bufbn.c \
    misc.c \
    bufaux.c \
    bufec.c

include(deployment.pri)
qtcAddDeployment()

HEADERS += \
    schnorr.h \
    log.h \
    includes.h \
    buffer.h \
    config.h \
    xmalloc.h \
    defines.h \
    misc.h



unix:!macx: LIBS += -L$$PWD/../../../Mydata/sourcecode/openssl-1.0.1j/ -lssl

INCLUDEPATH += $$PWD/../../../Mydata/sourcecode/openssl-1.0.1j
DEPENDPATH += $$PWD/../../../Mydata/sourcecode/openssl-1.0.1j

unix:!macx: PRE_TARGETDEPS += $$PWD/../../../Mydata/sourcecode/openssl-1.0.1j/libssl.a

unix:!macx: LIBS += -L$$PWD/../../../Mydata/sourcecode/openssl-1.0.1j/ -lcrypto

INCLUDEPATH += $$PWD/../../../Mydata/sourcecode/openssl-1.0.1j
DEPENDPATH += $$PWD/../../../Mydata/sourcecode/openssl-1.0.1j

unix:!macx: PRE_TARGETDEPS += $$PWD/../../../Mydata/sourcecode/openssl-1.0.1j/libcrypto.a


unix:!macx: LIBS += -ldl
