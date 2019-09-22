# learn-owasp-mstg-android

the memo of [owasp-mstg/Document/0x05b-Basic-Security_Testing.md](https://github.com/OWASP/owasp-mstg/blob/master/Document/0x05b-Basic-Security_Testing.md).

## Setting up a Testing Environment for Android Apps

前提として Android Studio がインストールされていること

#### Setting up the Android SDK

- Android SDK で対象のバージョンをインストールする
    - Android Studio で任意のプロジェクトを開き、Tools->Android->SDK Manager

#### Testing on a Real Device

- エミュレーターで検証することも可能だが、エミュレーターは実行速度が遅いため、実デバイスを使った方が良い。
- テストするデバイスは root 化しておくと良い。
    - ただし root 化には様々なリスクがあるので、安いテスト用の端末を購入して root 化するのがよい。Nexus シリーズなどで問題ない。
    - root 化の方法については割愛。Systemless な Magisk をおすすめしている。
- テスト用デバイスとプロキシを噛ませるためのホストマシンは同じ Wi-Fi ネットワーク上に存在する必要がある。
    - ネットワーク解析には Burp Suite を使う
    - Android 7以降、アプリケーションで指定されていない限り、Android OS はデフォルトでユーザー CA 証明書を信頼しなくなる。  
    次のセクションでは、このセキュリティ制御を回避する2つの方法について説明する。

#### Bypassing the Network Security Configuration

- Android 7 以降、ネットワークセキュリティ設定により、アプリがどのCA証明書を信頼するかを定義することができる
    - これは network_security_config.xml を設定することで実現できる
    - マニフェストも編集が必要
    - これらの変更を反映させるため、apktool でアプリのデコンパイル、リコンパイルを行う。
    - これらの手順を自動化した、Android-CertKiller という Python スクリプトがある。
        - APK を抽出、デコンパイルしてデバッグ可能にし、ユーザー証明書を許可する新しいネットワークセキュリティ設定を追加し、新しいAPKを作成、署名し、SSLバイパスで新しいAPKをインストールする。
        - 既知のバグにより、最後のステップであるアプリのインストールが失敗する可能性がある
- [この Magisk Module](https://github.com/NVISO-BE/MagiskTrustUserCerts) を使って、ユーザーがインストールした CA を system trusted CAs に自動で追加することができる。
- /system を mount して手動で行う手順も紹介。ただ Magisk で root 化する予定なので上記のモジュールを使う予定。

#### Testing on the Emulator

ざっと読んだが、実機を使うのでこの節は割愛。

## Testing Methods

#### Static Analysis

- Android アプリのブラックボックステストはホワイトボックステストとほぼ等価。なぜなら簡単にデコンパイルし、ソースコードを復元できるから。
- [apkx](https://github.com/b-mueller/apkx) は、コマンドラインから APK のソースコードを取得できるツール。
    - dex2jar とかを呼び出しているっぽいので、定常診断で作ったシェルスクリプトと同じようなものと思われる。
- ネイティブライブラリがない場合は静的解析は比較的容易だが、難読化が施されている場合はその限りではない。
- 静的解析はより高度に自動化されたツールを使うべきだ。オープンソーススキャナーから本格的なエンタープライズ対応スキャナーまで、多数の静的コードアナライザーが存在する。

#### Dynamic Analysis

- 動的解析はモバイルアプリの実行中に実行するもので、そのテストケースはファイルシステムの調査から通信の監視までさまざま。
- 最も重要なツールは OWASP ZAP や Burp Suite Professional などの interception proxies。interception proxies は、テスターに​​中間者の立場を与える。このポジションは承認やセッション、管理などのアプリのすべての要求とエンドポイント応答を読み取り、変更することができます。
- interception proxies を利用して中間者になりすましたとしても、そこには何も表示されない可能性がある。その原因は、アプリ側の制限によるものか Wi-Fi 側の client isolation の設定である可能性がある。
    - Wireless Client Isolation はワイアレスクライアントが互いに通信できないようにするセキュリティ機能
    - この機能が有効でテストができない場合、Android device 上で 127.0.0.1:8080 に対するプロキシを設定し、ラップトップとの adb 接続を使って reverse port forwarding することができる。  
    $ adb reverse tcp:8080 tcp:8080
    - この設定によって、Android device でのすべてのトラフィックは 127.0.0.1 のポート 8080 に送信され、ラップトップ側の adb 接続経由で 127.0.0.1:8080 にリダイレクトされ、interception proxies 上にトラフィックが表示される。
    - まだトラフィックが傍受できない場合は、前述のアプリ側の制限である可能性がある。考えられるのは以下の２つ。いずれの場合も追加の対処が必要になる。
        - Xamarin のような Android OS のプロキシ設定を使用していないフレームワークを使用しているケース。
        - アプリ側で既にプロキシが設定されていてその他の communication を許可していないケース。

#### iptables

- Android デバイス場の iptables を使って、interception proxies にトラフィックをリダイレクトする。  
    $ iptables -t nat -A OUTPUT -p tcp --dport 80 -j DNAT --to-destination <Your-Proxy-IP>:8080
    - そのあと、iptablesの設定を確認し、IPとポートを確認する  
```
$ iptables -t nat -L
Chain PREROUTING (policy ACCEPT)
target     prot opt source               destination

Chain INPUT (policy ACCEPT)
target     prot opt source               destination

Chain OUTPUT (policy ACCEPT)
target     prot opt source               destination
DNAT       tcp  --  anywhere             anywhere             tcp dpt:5288 to:<Your-Proxy-IP>:8080

Chain POSTROUTING (policy ACCEPT)
target     prot opt source               destination

Chain natctrl_nat_POSTROUTING (0 references)
target     prot opt source               destination

Chain oem_nat_pre (0 references)
target     prot opt source               destination
```
- iptables の設定をリセットしたいときは、以下のコマンドで設定をフラッシュする。  
$ iptables -t nat -F

#### Ettercap

- さらなる準備と Ettercap の実行方法については、Testing Network Communication" and the test case "Simulating a Man-in-the-Middle Attack" を参照（と書きつつ、そのあとに Ettercap の準備が続く）
    - プロキシを起動しているマシンと Android デバイスは同じワイヤレスネットワークに接続されている必要がある。  
    以下のコマンドで ettercap を起動し、以下の IP アドレスを Android デバイスとワイヤレスネットワークのゲートウェイの IP アドレスに置き換える。  
    $ sudo ettercap -T -i en0 -M arp:remote /192.168.0.1// /192.168.0.105//

#### Bypassing Proxy Detection

- 一部のモバイルアプリはプロキシの設定を検出しようとする。
    - これを迂回するためには、bettercap を設定するか、Android device にプロキシ設定を必要としない iptables を設定することができる。
    - そしてもう一つの選択肢は Frida。
    - Android では、ProxyInfo クラスを getHost（）メソッドとgetPort（）メソッドで検索してシステムプロキシが設定されているかどうかを検出することができる。
    - このような検出方法は他にもさまざまな方法があり、実際のクラスとメソッド名を識別するためには APK をデコンパイルする必要がある。
    - 以下 Frida スクリプトのボイラープレート(?)のソースコード。これはプロキシが設定されているかどうかを確認するメソッドをオーバーライドして、常に false を返すようにしている。  
```
setTimeout(function(){
    Java.perform(function (){
        console.log("[*] Script loaded")

        var Proxy = Java.use("<package-name>.<class-name>")

        Proxy.isProxySet.overload().implementation = function() {
            console.log("[*] isProxySet function invoked")
            return false
        }
    });
});
```

Frida は[公式ドキュメント](https://www.frida.re/docs/quickstart/)を読みながら進めた。
pipenv で Python 3.6.5 の環境にインストールし、チュートリアルの Functions を実施。#10109 と併せて読むと効率的に理解できる。

追加で公式の [Android](https://www.frida.re/docs/android/) も一通り流す。
get_usb_device().attach で USB 越しにフックすることが可能だが、frida-server をデバイス上で起動することでも可能。GDB っぽい。

リリースページから frida-server-12.4.8-android-arm64 をダウンロードし、/data/local/tmp に移送してパーミッションを付与。
adb root コマンドがエラーとなったのでページの手順とは少し異なるが、adb でデバイスに接続して root になってから frida-server を起動。
frida-ps -U で実行しているプロセスの一覧を取得できるので、これがラップトップから確認できればサーバーは正常に起動している状態。

#### Network Monitoring/Sniffing

- [tcpdump、netcat、Wireshark を使うと Android のトラフィックをリモートでリアルタイムに傍受できる。](https://blog.dornea.nu/2015/02/20/android-remote-sniffing-using-tcpdump-nc-and-wireshark/)
- まず、Android デバイスの tcpdump を最新のものにする。最新のバイナリはここからダウンロード。  
手順は詳細に記載されている通りに実施。  
listening on dummy0, link-type EN10MB (Ethernet), capture size 262144 bytes  
と表示されたが、そのあとにブラウジングしても特に何も表示されない・・・  
うまくいってないと思われる。

- リモートで傍受するには、tcpdump の結果を netcat に渡す。  
tcpdump -i dummy0 -s0 -w - | nc -l -p 11111  
dummy0 インタフェースをリッスンし、キャプチャのサイズを everything (-s0) で指定し、-w の出力（書き込み）をパイプで nc に渡している。  
そして adb でポートフォワーディングしておき  
adb forward tcp:11111 tcp:11111  
Wireshark に流し込む  
nc localhost 11111 | wireshark -k -S -i -  
しかし Wireshark で End of file on pipe magic during open. というエラーに・・・やはり上手くいってないな。  
Wi-Fi を町営のものに変えてみたが挙動は変わらず。凡ミスっぽいが時間が勿体無いのでこのまま先に進む。  
- Burp plugins to Process Non-HTTP Traffic  
Burp や OWASP ZAP では non-HTTP traffic には対応していないが、プラグインを利用することができる。

#### Preparation of Test Setup

- iptables を設定するか、ettercap を使う必要がある。
- 以降は Firebase Cloud Messaging のキャプチャを取る作業だが、自分の作業範囲か分からないことと上述の tcpdump が上手くいっていない問題もあるので一旦保留。

