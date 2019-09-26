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
        - APK を抽出、デコンパイルしてデバッグ可能にし、ユーザー証明書を許可する
        - 新しいネットワークセキュリティ設定を追加し、新しいAPKを作成、署名し、SSLバイパスで新しいAPKをインストールする。
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

#### End-to-End Encryption for Push Notifications

- Drozer は、Android のアプリのセキュリティ脆弱性をセキュリティ評価のフレームワーク。
    - Mac では、依存関係の問題から少しインストールが難しい。El Capitan 以降の Mac OS では OpenSSL がインストールされていないので、まずこれを手動でインストールする。
    - また、Drozer は古いバージョンの Python ライブラリに依存しているので、virtualenv を使ってください。
    - pyOpenSSL バージョンの Drozer のソースにタイプミスがあると、正常にコンパイルできなくなるので、コンパイルする前にソースを修正する必要がある。
    - 詳細な手順は載っているので問題ない・・・と思っていたら easy_install でエラーになった。
        - Missing parentheses in call to 'print'. というエラーが出ていたが、これは2系の Python スクリプトを3系の環境で動かした時によく出るやつ。公式のページを見ると、Prerequisites に Python2.7 と書いてあった。
        - Mac ではデフォルトで 2.7 が入っているが、自分で 3 系をインストールしてデフォルトに設定している人は virtualenv drozer のコマンドを virtualenv drozer --python=/usr/bin/python2.7 とする必要がある。
    - Drozer agent をダウンロードし、adb でデバイスにインストールする。
    - インストールしたアプリをデバイス上で開き、画面下部にある[OFF]ボタンをクリックして Embedded Server を起動する。
    - サーバーはデフォルトでポート 31415 で待機しているので、adb でポートフォワードして接続する。
```
$ adb forward tcp:31415 tcp:31415
$ drozer console connect
```

#### Basic Drozer Commands:

基本的な使い方は以下のポストが参考になる。
[How To Test Android Application Security Using Drozer?](https://medium.com/@ashrafrizvi3006/how-to-test-android-application-security-using-drozer-edc002c5dcac)

#### Using Modules: / Finding Modules: / Installing Modules:

- Drozer は追加モジュールをダウンロードできる。公式のモジュールであれば module コマンドで検索が可能。
- 新しくインストールしたモジュールは動的にロードされるのでインストール後にすぐに使える。

#### Potential Obstacles

- アプリケーションはしばしば rooted detect や証明書の検証などを行うセキュリテイ機能が実装されている。
- 診断にあたっては、これらの機能があるものと、除去したものの両方を入手することが望ましい。
- すべてのセキュリティ対策が有効になっているアプリケーションでは、ブラックボックス評価を実行することになる。次のセクションではこれらのセキュリティ対策をバイパスする。
- Certificate Pinning
    - アプリが証明書のピン留めを実装している場合、プロキシによって提供された X.509 証明書は拒否され、アプリはプロキシを介した要求を拒否する。
    - デバイスで利用可能なフレームワークに応じて、ブラックボックステストのために証明書の固定を回避する方法がある。
        - Frida: [Objection](https://github.com/sensepost/objection)
        - Xposed: TrustMeAlready, SSLUnpinning
        - Cydia Substrate: Android-SSL-TrustKiller
    - ほとんどのアプリではこのピン留めは一瞬で回避できるが、これらのツールでカバーされているAPI機能を使用している場合に限られる。
    - アプリがカスタムフレームワークまたはライブラリを使用してSSL固定を実装している場合は、手動でパッチを適用して無効化する必要がある
    - 静的解析で回避することもできる。
        - まずはアプリをデコンパイルして、smali の中から検索する。  
        grep -ri "sha256\|sha1" ./smali
        - 見つけたハッシュ値をプロキシの CA のハッシュで書き換え。ハッシュにドメイン名が付随している場合は、元のドメインが固定されないようにドメイン名を存在しないドメインに変更する。これは難読化されたOkHTTP実装ではうまく機能する。
        - 次に、証明書ファイル：./assets -type f \（-iname \ *。cer -o -iname \ *。crt \）を見つける。これらのファイルをプロキシの証明書と置き換える。
        - アプリケーションがネットワーク通信の実装にネイティブライブラリを使用している場合は、さらに解析が必要。
        - これらが完了したら、アプリをリコンパイルしてデバイスにインストールする。
    - Bypass Custom Certificate Pinning Dynamically
        - 動的解析だと改変検知をバイパスする必要がないので便利
        - 難読化されている場合はフックする API を見つけるのが困難なので、使用されているライブラリを識別する文字列とライセンスファイルを検索するのがグッドパターン。  
        ライブラリを特定したら、元のソースコードを調べて動的計測に適したメソッドを探す。
        - Frida で各メソッドをフックして引数を出力するとドメイン名と証明書ハッシュが出てくるので、それを改ざんする。
- Root Detection
    - [Testing Anti-Reversing Defenses on Android](https://github.com/OWASP/owasp-mstg/blob/master/Document/0x05j-Testing-Resiliency-Against-Reverse-Engineering.md) を参照。
        - 非常に長いドキュメントだが、いくつかの rooted 検知回避を試すことで検知方法はある程度割れるだろう。

---

[Hacking Android apps with FRIDA II - Crackme](https://www.codemetrix.io/hacking-android-apps-with-frida-2/) を教科書に Frida のフックテスト。  
[owasp-mstg/Crackmes/](https://github.com/OWASP/owasp-mstg/tree/master/Crackmes) の level 1 を定常診断のツールでデコンパイルし、JD-GUI でパスワードの正解を生成しているメソッドを発見。  
```
package sg.vantagepoint.a;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

public class a
{
  public static byte[] a(byte[] paramArrayOfByte1, byte[] paramArrayOfByte2)
  {
    paramArrayOfByte1 = new SecretKeySpec(paramArrayOfByte1, "AES/ECB/PKCS7Padding");
    Cipher localCipher = Cipher.getInstance("AES");
    localCipher.init(2, paramArrayOfByte1);
    return localCipher.doFinal(paramArrayOfByte2);
  }
}
```
rooted 検知は上手くバイパスできなかったので Magisk Hide でバイパスし、 Javascript で上記の関数をフックして生成した鍵を吐き出す。
```
setImmediate(function () { //prevent timeout
  console.log("[*] Starting script");

  Java.perform(function () {

    aaClass = Java.use("sg.vantagepoint.a.a");
    aaClass.a.implementation = function (arg1, arg2) {
      retval = this.a(arg1, arg2);
      password = ''
      for (i = 0; i < retval.length; i++) {
        password += String.fromCharCode(retval[i]);
      }

      console.log("[*] Decrypted: " + password);
      return retval;
    }
    console.log("[*] sg.vantagepoint.a.a.a modified");
  });
});
```
アプリを正常に動作させるため、フックした関数でもちゃんと return retval; を実装している。  
デバイス上でアプリを起動したあとに、以下のコマンドラインでインジェクション。  
```
frida -U -l uncrackable1.js owasp.mstg.uncrackable1
```
そのあとにアプリの VERIFY ボタンをタップし、照合メソッドを実行する。  
```
[LGE Nexus 5X::owasp.mstg.uncrackable1]-> [*] Starting script
[*] sg.vantagepoint.a.a.a modified
[*] Decrypted: I want to believe
```

---

[このページ](https://qiita.com/ymmtyuhei/items/b68e35a21f7c1252dca8)を参考に以下のコマンドで tcpdump の結果を取得できた。
```
tcpdump -s 0 -i wlan0 -v -w /sdcard/dump.pcap
```

このファイルを Wireshark で読み込めることも確認。  
