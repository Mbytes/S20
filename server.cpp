/*************************************************************************
 *  Copyright (C) 2015 by Andrius Štikonas <andrius@stikonas.eu>         *
 *                                                                       *
 *  This program is free software; you can redistribute it and/or modify *
 *  it under the terms of the GNU General Public License as published by *
 *  the Free Software Foundation; either version 3 of the License, or    *
 *  (at your option) any later version.                                  *
 *                                                                       *
 *  This program is distributed in the hope that it will be useful,      *
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of       *
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the        *
 *  GNU General Public License for more details.                         *
 *                                                                       *
 *  You should have received a copy of the GNU General Public License    *
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.*
 *************************************************************************/

#include <QNetworkConfiguration>
#include <QNetworkConfigurationManager>
#include <QNetworkSession>
#include <QTimer>
#include <QUdpSocket>

#include "consolereader.h"
#include "server.h"

Server::Server(std::vector<Socket*> *sockets_vector)
{
    sockets = sockets_vector;
    udpSocketGet = new QUdpSocket(this);
    udpSocketGet->bind(QHostAddress::Any, 10000);
    connect(udpSocketGet, &QUdpSocket::readyRead, this, &Server::readPendingDatagrams);
    discoverSockets();
    QTimer *discoverTimer = new QTimer(this);
    discoverTimer->setInterval(1 * 60 * 1000); // 1 min
    discoverTimer->setSingleShot(false);
    connect(discoverTimer, &QTimer::timeout, this, &Server::discoverSockets);
    discoverTimer->start();

    start();
}

Server::Server(uint16_t port, QByteArray ssid, QByteArray password)
{
    QNetworkConfiguration *cfgInitial = new QNetworkConfiguration;
    const QNetworkConfiguration *cfg = new QNetworkConfiguration;
    QNetworkConfigurationManager *ncm = new QNetworkConfigurationManager;
    ncm->updateConfigurations();
    *cfgInitial = ncm->defaultConfiguration();

    if (ssid == "c") {
        ssid = cfgInitial->name().toLocal8Bit();
        qDebug() << "SSID unspecified, using current network: " << ssid;
    }

    bool stop = false;
    while (!stop) {
        QThread::sleep(1);

        const auto nc = ncm->allConfigurations();

    for (const auto &x : nc) {
            if (x.bearerType() == QNetworkConfiguration::BearerWLAN) {
                if (x.name() == "WiWo-S20") {
                    qDebug() << "Connecting to WiWo-S20 wireless";
                    cfg = &x;
                    stop = true;
                }
            }
        }
    }

    QNetworkSession *session = new QNetworkSession(*cfg, this);
    session->open();
    qDebug() << "Wait for connected!";
    if (session->waitForOpened())
        qDebug() << "Connected!";

    QUdpSocket *udpSocketSend = new QUdpSocket();
    udpSocketGet = new QUdpSocket();
    udpSocketGet->bind(QHostAddress::Any, port);

    QByteArray reply;

    qDebug() << "Send: HF-A11ASSISTHREAD";
    udpSocketGet->writeDatagram(QByteArray::fromStdString("HF-A11ASSISTHREAD"), QHostAddress::Broadcast, port);
    reply = listen(QByteArray::fromStdString("HF-A11ASSISTHREAD"));
    QList<QByteArray> list = reply.split(',');
    QHostAddress ip(QString::fromLatin1(list[0]));
    qDebug() << "IP: " << ip.toString();
    qDebug() << "Send: +ok";
    udpSocketGet->writeDatagram(QByteArray::fromStdString("+ok"), ip, port);
    qDebug() << "Send: AT+WSSSID=" + QString::fromLatin1(ssid) + "\r";
    udpSocketGet->writeDatagram(QByteArray::fromStdString("AT+WSSSID=") + ssid + QByteArray::fromStdString("\r"), ip, port);
    listen();
    qDebug() << "Send: AT+WSKEY=WPA2PSK,AES," + QString::fromLatin1(password) + "\r";
    udpSocketGet->writeDatagram(QByteArray::fromStdString("AT+WSKEY=WPA2PSK,AES,") + password + QByteArray::fromStdString("\r"), ip, port);    // FIXME: support different security settings
    // OPEN, SHARED, WPAPSK......NONE, WEP, TKIP, AES
    listen();
    qDebug() << "Send: AT+WMODE=STA\\r";
    udpSocketGet->writeDatagram(QByteArray::fromStdString("AT+WMODE=STA\r"), ip, port);
    listen();
    qDebug() << "Send: AT+Z\\r";
    udpSocketGet->writeDatagram(QByteArray::fromStdString("AT+Z\r"), ip, port);    // reboot
    listen();
    session->close();
    // FIXME: discover the new socket
    qWarning() << "Finished";
    session = new QNetworkSession(*cfgInitial, this);
    session->open();
    if (session->waitForOpened())
        qWarning() << "Connected";
    discoverSockets();
}

QByteArray Server::listen(QByteArray message)
{
    QByteArray reply;
    QHostAddress sender;
    quint16 senderPort;
    bool stop = false;
    while (!stop) {
        QThread::msleep(50);
        while (udpSocketGet->hasPendingDatagrams()) {
            reply.resize(udpSocketGet->pendingDatagramSize());
            udpSocketGet->readDatagram(reply.data(), reply.size(), &sender, &senderPort);
            qDebug() << "Reply: " << QString::fromLatin1(reply.data());
            if (reply != message) {
                stop = true;
            }
        }
    }
    return reply;
}

void Server::run()
{
    readPendingDatagrams();
}

void Server::readPendingDatagrams()
{
    while (udpSocketGet->hasPendingDatagrams()) {
        QByteArray reply, mac;
        reply.resize(udpSocketGet->pendingDatagramSize());
        QHostAddress sender;
        quint16 senderPort;

        udpSocketGet->readDatagram(reply.data(), reply.size(), &sender, &senderPort);

        if (reply != discover && reply.left(2) == magicKey) {    // check for Magic Key
            if (reply.mid(4, 2) == QStringLiteral("qa").toLatin1() || reply.mid(4, 2) == QStringLiteral("qg").toLatin1()) {      // Reply to discover packet
                bool duplicate = false;
                for (const auto &socket : *sockets) {
                    if (socket->ip == sender) {
                        duplicate = true;
                        break;
                    }
                }
                if (!duplicate) {
                    Socket *socket = new Socket(sender, reply);
                    sockets->push_back(socket);
                    std::sort(sockets->begin(), sockets->end(), [](const Socket* a, const Socket* b) -> bool { return QString::compare(QString(a->mac), QString(b->mac)) < 0 ? true : false; }); // socket name is not known yet
                    Q_EMIT discovered();
                }
                mac = reply.mid(7, 6);
            } else {
                mac = reply.mid(6, 6);
            }
            for (const auto &socket : *sockets) {
                if (socket->mac == mac) {
                    socket->parseReply(reply);
                    break;
                }

            }
        }
    }
}

void Server::discoverSockets()
{
    QUdpSocket *udpSocketSend = new QUdpSocket(this);
    udpSocketSend->connectToHost(QHostAddress::Broadcast, 10000);
    udpSocketSend->write(discover);
    udpSocketSend->write(discover);
    udpSocketSend->disconnectFromHost();
    delete udpSocketSend;
}

void broadcastPassword(QString password)
{
    QUdpSocket *udpSocket = new QUdpSocket();
    udpSocket->connectToHost(QHostAddress::Broadcast, 49999);
    uint sleep = 15;
    for (uint j = 0; j < 4; ++j) { // FIXME: stopping loop on discovery
        qWarning() << j;
        for (unsigned short int i = 0; i < 200; ++i) {
            udpSocket->write(fives(76));
            QThread::msleep(sleep);
        }
        for (unsigned short int i = 0; i < 3; ++i) {
            udpSocket->write(fives(89));
            QThread::msleep(sleep);
        }

        QChar *data = password.data();
        while (!data->isNull()) {
            udpSocket->write(fives(data->unicode() + 76));
            QThread::msleep(sleep);
            ++data;
        }
        for (unsigned short int i = 0; i < 3; ++i) {
            udpSocket->write(fives(86));
            QThread::msleep(sleep);
        }
        for (unsigned short int i = 0; i < 3; ++i) {
            udpSocket->write(fives(332 + password.length()));
            QThread::msleep(sleep);
        }
    }

    udpSocket->disconnectFromHost();
    delete udpSocket;
    // FIXME: special slightly modified SocketData packet might is needed here
}

QByteArray fives(unsigned short int length)
{
    QByteArray packet;
    packet.fill(0x05, length);
    return packet;
}
