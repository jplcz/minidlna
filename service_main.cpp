#include "config.h"
#include "minidlna.h"
#include <cstdio>
#include <cstdlib>
#include <exception>

#ifdef MINIDLNA_QT
#include <QCoreApplication>
#endif

int main(int argc, char **argv) {
  try {
#ifdef MINIDLNA_QT
    // Set basic properties of QApplication
    QCoreApplication::setApplicationName(QStringLiteral(QTAPP_SERVICE_NAME));
    QCoreApplication::setOrganizationDomain(
        QStringLiteral(QTAPP_PROJECT_DOMAIN));
    QCoreApplication::setOrganizationName(QStringLiteral(ROOTDEV_MANUFACTURER));
    QCoreApplication::setApplicationVersion(
        QStringLiteral(QTAPP_PROJECT_VERSION));
    // Initialize Qt internals
    QCoreApplication app(argc, argv);
#endif
    return service_main(argc, argv);
  } catch (std::exception &ex) {
    fprintf(stderr, "Terminated because of: %s\n", ex.what());
    return EXIT_FAILURE;
  }
}
