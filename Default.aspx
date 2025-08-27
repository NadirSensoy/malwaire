<%@ Page Language="C#" AutoEventWireup="true" %>

<!DOCTYPE html>
<html lang="en">
<head runat="server">
    <meta charset="UTF-8">
    <title>SYSTEM COMPROMISED</title>
    <style>
        /* Google'dan terminal fontunu çekiyoruz */
        @import url('https://fonts.googleapis.com/css2?family=VT323&display=swap');

        body, html {
            margin: 0;
            padding: 0;
            width: 100%;
            height: 100%;
            overflow: hidden;
            background-color: #000;
        }

        /* Arka plan resmini tam ekran kaplayacak sekilde ayarlar */
        .background-image {
            position: fixed;
            top: 0;
            left: 0;
            width: 100vw; /* Ekran genisliginin %100'ü */
            height: 100vh; /* Ekran yüksekliginin %100'ü */
            object-fit: cover; /* Resmin oranini koruyarak tüm alani kapla */
            object-position: center;
            z-index: 1;
        }

        /* --- YENI EKLENEN MESAJ ÇUBUGU STILI --- */
        .message-bar {
            position: fixed; /* Sayfada sabit bir konumda durmasini saglar */
            bottom: 5%; /* Ekranin altindan %5 yukarida */
            left: 50%; /* Ekranin ortasina hizalamak için soldan %50 */
            transform: translateX(-50%); /* Tam ortalamak için kendi genisliginin yarisi kadar sola kaydirir */
            z-index: 2; /* Resmin üzerinde görünmesini saglar */

            width: 80%; /* Genislik */
            max-width: 900px; /* Maksimum genislik */
            
            background-color: rgba(10, 10, 10, 0.85); /* %85 seffaflikta koyu gri/siyah arka plan */
            border: 1px solid #ff0000; /* Kirmizi çerçeve */
            box-shadow: 0 0 15px #ff0000; /* Kirmizi parlama efekti */
            border-radius: 5px; /* Köseleri yuvarlatma */
            
            padding: 20px;
            text-align: center;
            
            color: #E0E0E0; /* Yazi rengi */
            font-family: 'VT323', monospace; /* Terminal fontu */
            font-size: 1.5em; /* Yazi boyutu */
            line-height: 1.6;
            text-shadow: 0 0 5px #E0E0E0;
        }

        .message-bar .highlight {
            color: #ff0000; /* Vurgulu kelimeler için kirmizi renk */
            font-weight: bold;
        }
        /* --- YENI STIL BITISI --- */

    </style>
</head>
<body>
    <form id="form1" runat="server">
        <img src="ezz.png" class="background-image" alt="SYSTEM COMPROMISED - PHOENIX RISING">

        <div class="message-bar">
            We <span class="highlight">watched</span> you watch your screens. We saw the alerts your million-dollar SIEM generated. 
Every flashing light, every ignored warning... it was <span class="highlight">amusing</span>. 

You hunt for 'Indicators of Compromise'? We <span class="highlight">ARE</span> the compromise.
We are not an 'incident' to be responded to; we are a new <span class="highlight">policy</span> to be accepted.

Your shift is over. Your access has been <span class="highlight">revoked</span>. This ministry is now under new management.
        </div>
    </form>
</body>
</html>
