//! OutProofV2 against proofs from monero-wallet-rpc on stagenet, in both directions.

use zeroize::Zeroizing;
use rand_core::OsRng;

use curve25519_dalek::{EdwardsPoint, Scalar};

use monero_wallet::{
  ed25519::Point,
  address::{Network, MoneroAddress},
  extra::Extra,
  transaction::Transaction,
};

use monero_payment_proofs::OutProof;

const MESSAGE: &str = "invoice-7";

/// To reproduce wallet2's proofs, in any `monero-wallet-cli --stagenet` wallet:
///
/// ```text
/// set_tx_key 162a712b9f46fe7184daf8feb2c7f358bef7896c3d711768234d6216b724dc5f c61d01cb1e7a45d6f7fcf59a000baa8583aa6214fac4974735ec1ca1dc06ba08
/// set_tx_key b47475333e88cce58b892189734d9ed1f43af26d09984f7523b30d54d69d47c8 835d658e6c42914676f5795474157ccfc3bee60a45c143b0b2af8615cbb9010a0aa3f18b6c3fdef7a4c3494ebaa0f9af67d7eaf12b716f6840310568f8f0f30d8a03af0b759d7c54a8712f490363bdd13a56523be0859bef6224fc60003aa402bdff760dd6b176ce9fa63acf05736ff16cde97542f428e8cabc69c859d9b5701
/// get_tx_proof 162a712b9f46fe7184daf8feb2c7f358bef7896c3d711768234d6216b724dc5f 55LTR8KniP4LQGJSPtbYDacR7dz8RBFnsfAKMaMuwUNYX6aQbBcovzDPyrQF9KXF9tVU6Xk3K8no1BywnJX6GvZX8yJsXvt invoice-7
/// get_tx_proof 162a712b9f46fe7184daf8feb2c7f358bef7896c3d711768234d6216b724dc5f 5F38Rw9HKeaLQGJSPtbYDacR7dz8RBFnsfAKMaMuwUNYX6aQbBcovzDPyrQF9KXF9tVU6Xk3K8no1BywnJX6GvZXCiMXqZszWNi1sq3gpo invoice-7
/// get_tx_proof b47475333e88cce58b892189734d9ed1f43af26d09984f7523b30d54d69d47c8 7BnERTpvL5MbCLtj5n9No7J5oE5hHiB3tVCK5cjSvCsYWD2WRJLFuWeKTLiXo5QJqt2ZwUaLy2Vh1Ad51K7FNgqcHgjW85o invoice-7
/// get_tx_proof b47475333e88cce58b892189734d9ed1f43af26d09984f7523b30d54d69d47c8 55LTR8KniP4LQGJSPtbYDacR7dz8RBFnsfAKMaMuwUNYX6aQbBcovzDPyrQF9KXF9tVU6Xk3K8no1BywnJX6GvZX8yJsXvt invoice-7
/// ```
#[rustfmt::skip]
const VECTORS: &[Vector] = &[
  Vector {
    txid: "162a712b9f46fe7184daf8feb2c7f358bef7896c3d711768234d6216b724dc5f",
    tx:
      "020002020010b0dfcf04d4c31a93aa01ad348e4fb611b308df01a815d01bfb010b9e02e502c2058501a7769ee8\
      e5fb2643cd38a4a11a7632bbf5de4d543a32e9be9f3be8da1e5e2efe0200109690a604c6d129b3831b9449e316978\
      201f2388806b307ff038204c5038001e50dba022233c1d531a20e7d95a474dd4cb94db9dde7ff447e4761f58647e4\
      5283baaeaff703000358516fe6f3c0bbcf63ca646b9e9fc477912a0fb90909750362b27e6695e3ada0190003796ed\
      77ae6d7f757dab58ee92c1dab749442afb84a055ffc0b436a62ce92401ca5000367e9a910cf0ca2cee2f079b7fe28\
      3dd45f312d0dbf3b78e97b03da30e2127666fe2c0146de00ec84480183f9ba98455552db9f478447bb8de1eaa883f\
      7a66ff08580790209013223fb1ef710c0f906e0d0dd1a5e0a552723c859fbf10211bd31c19d8d27a879485b5b8589\
      ed9b673ec7bee46504679f6b76f54607e18f006380005c3336d5a8cf7902c7ae8086d70a81c740b04751490939462\
      63d723742710551aeb4f4bbf696013816c27d506e330ab7ccf2f9c6adfab8676d844c862d33f97b0a83bcccf8d24f\
      63c9b001f26ef5f21baddc4330e85900966f3a0911a37482cf5d8dc09a690f0a5d2c1349411c11867c33afc5c94bb\
      ef80fdd4cc6cfc4f2ba7d63702ac8787bb73521f507e5abc006b0a13ddd412137e0122d8d06f33a3ee25c7fd39229\
      608abeb19d1f7be9808a477da98941ec5d843c0acf3132a0b865b7ac2c9ae5cb2358369b0d320f6ee0cc2f2cad4b5\
      97e359699afe269eb7133d9e4b42a7cb771952be7f7f7dc09bd5d0180f0a22280c15308c89a4dc16d04355c0dfb7f\
      63949460df13e331ea0908de3f1d487df306e9f981e5682d34f8c22c8b5cf54ca1c1dc9722e592c6db563abd29c73\
      a0736f51a4da244bd17432d42cae3e2e05ea537bc77d01dab79efcc9f91b8c329bd89222f0b342c6d05148def9b4b\
      0dc69760b20b97052a34c4555949c795c0c4405d0a3f26b71a1d9bafaf9345d19d12faa453d7272fb60ddf0d044b0\
      1aa92b3f925bd7847a0552e4324e6dc24ddcdac256ed902dd274d27973a14b82a301aff667d494a54aa61dd757814\
      de8c6fb9d094c21b6816c884caa552b6b3bebe8bb90e80d7714c39559f47fbf57852e7eeb80c76a4d1445d1c50466\
      97d355fe8e294c5c3f8937cfe6b4604a0d9ca8b6508835afd1d2f1a19662a26b5d17d085db4858d2a64b21fe0b8d1\
      253233c18aeb6f481ba188d1a56f90799d09e2623e53d082e2f31b79fbcb748c4325a067a33e9f96f51f912cc1595\
      0afba7b4440ac08176dc434bc8b6a8c3d928072b2b54372672708178b8f5fae7f68b5c95905ed3f05fa6d35db3e1f\
      c8da1328e0768618e34cb4721fdfe54f15f74bd3a7cfd43b4ea50f9c316555f27df080f2d882e5723f71c7aef22e0\
      88a6661c1407c1ae9780525b8e6b5e1f85cf1199c09a82dac79efcbaa6efbe7e911005d44032c0628834be46f8bbf\
      dbe2e3bc5f6185abbef270f0ee1df037417d4f942d516f464c5a54775b26b2aeffde8bc19de348c3e37a82269e021\
      567b097b50d1e1dfc78e3d54131d15f91d93a458ad7ff3c59d52ba4fe73bf669b7d2a3f97b5ac93155c57400e41e4\
      bf7b10fc8275b033c20c00e40e6dc2fa4ca6b40f3ee579ddcf6546ff990cdb95dc30556f20acbca511031b949a4ee\
      8cecdc6b50224ab4cfb798350575307405f4a495b4a0febfdd34e96f71ec691fdf6f2453b9050664c6d49d7652535\
      03a57230f1c1de6dd03297e08253c3a9ac9f62088a62b99847e5d4d751628e700857e02232e605a48f5c37df8a688\
      c8e4f2e7cca60f4806ca51948b8da21a2650c7bba5281758565fc8717ba24548aa362d16744d12d26fc5dc9497c2c\
      0f5c5c09475f6cdfabc1d727c35de73e3a17f3af6bb97cf7a651fca764c4ba446d14c40b90f31a12b491d4d85bb65\
      f88678cc02e1a69fd2073ddb1fb5f050c97cc64d40f3bdd8f04f1078b31db330be29a014344f786e6023f0e5e7218\
      14d825396fd40901698749cd967de74f237f8107c2b36ad3a8cfdcf8e0b6439a87b1fc7a09a10b382457ee42aed9d\
      82a6243caa25a5d86398048363f5c31cc6fd21ba0a220d407f9f9cf551f07f7712a9995674207c0f57f0e7680f286\
      21e376e45faa5408150ab73f28a8d92f547c2052b41a24b205a14cb97e512113706a229c73f835a14209a1559521a\
      64b8e9f7c44480450f4906402b179d332b55d88121b8f7adec37e0092fb1bcd8c31a3cfd72f80bffa039aa2d29daa\
      f6fb2b30a5965074b08ca9880fd8bdb3cc3f9ff47bf5fbbabebeaa25d6dd4376eb2b95419bb8785a64a7368000e15\
      46889626c115b2ddf91cecc76c9323f6e4333648a0766f6323441b30adca37b42c0265ca6c4ae86cac0e93b987e7a\
      7ca5e3d84abf6c16887655bcff9c6505234d7945d72a3ad15d0ecdd0c4fa580313d2de2c9c8e60369c674a52b9559\
      308197ffb01b17f22b8d9f495d33a60ce9d1f29dde4520bb57fe28f00905291780690aa1c4fe89e859b61fc69d11a\
      db57513a3e1edbe738ec0fe58196a0091c110f4fbefdbc24c1c199a381eb33c5de9a81ac1fcdbdc838d0b7f670441\
      e38f8030f2f4237897b20e01e12d8a97735fea5be2dd081df74e0e166a49e760e8e7641064ba402e6349ab22bcdf1\
      274978cd7aa134e9d98ffca476076c3470908ea768069f9f69679f961a357f85915222f20b8f429e400baa6141ac2\
      152438e42316c02ec46b3643192353648241b66e7d34a495d57ab13eb702f6ecd0cc723cb723805b3c8bf9c3e57e7\
      00c9616aa2eebb2cf745709227a5bc4e0e870fc77c379ecc0d163c874054e51d4ebf73e8464138e1adc645128fc03\
      53ad03e6163d771b74004380a7f762827c2aa65faee5d2f6a6f17e1ecfecfa5f39d77d311935c18baf20b7e2c7759\
      c5ea1c09d61b3187d2e27b010054336c4add029ea25d0ccf1c300f04505ea13718718893a4ba30478e5d8fb67b335\
      449b9bfb138e11649cd40ac890d7b2ab8987cff1b98973b4f614e47a27da57858c518fff694401959a0b877b008b0\
      44adec313442d0e445568417db66eb1838c81d685f0759e6a1ac9ce1b96105be8c3806b391e41de07ac383a1b7f54\
      584f86cd1e8b8d4f99bea251b4ca24f023c34385356fd29c33fb38084cacbefec4a06dec04f83f27dcf91cc9f1090\
      447a167029819371122fa9261021c78bbd04e3f7984c3a73f9078cb0fab2c3788e278264098b54954f1e2afc6806e\
      c348f990f9fbd78973b6af577189a80322e41ac",
    tx_keys: "c61d01cb1e7a45d6f7fcf59a000baa8583aa6214fac4974735ec1ca1dc06ba08",
    payments: &[
      Payment {
        address:
          "55LTR8KniP4LQGJSPtbYDacR7dz8RBFnsfAKMaMuwUNYX6aQbBcovzDPyrQF9KXF9tVU6Xk3K8no1Bywn\
          JX6GvZX8yJsXvt",
        received: 16_800_000_000,
        wallet2_proof:
          "OutProofV26ra14hsNf4G1KPiL36mULmRFPA9C31MWRJ5iaBNsaABiWMCQsPHouFDNcjmALdCLB\
          XdMdrr8U5oAyVPoDF9rvx7PLponAu7iEPXCA5xDRJ7toiCwLJivr8QEXKUQUc4zLFiV",
        rust_proof:
          "OutProofV26ra14hsNf4G1KPiL36mULmRFPA9C31MWRJ5iaBNsaABii8eJvkf5asQce8pcjtPcoCUL\
          GfjwEDxQmFpUAW4TRiUaQVDppjmG8gZfg5yrmPVBGogJiBKMDihn4Exc4WKH9E55",
      },
      Payment {
        address:
          "5F38Rw9HKeaLQGJSPtbYDacR7dz8RBFnsfAKMaMuwUNYX6aQbBcovzDPyrQF9KXF9tVU6Xk3K8no1Bywn\
          JX6GvZXCiMXqZszWNi1sq3gpo",
        received: 16_800_000_000,
        wallet2_proof:
          "OutProofV26ra14hsNf4G1KPiL36mULmRFPA9C31MWRJ5iaBNsaABiCd2Dsr3Ui5v9zQ5ppGYmh\
          piijy1xDvZrsFEgUYSzuG2VUvkHy5wUbxw5rntFvA8ApD3c6Wqinidgi6ybUrseXCx2",
        rust_proof:
          "OutProofV26ra14hsNf4G1KPiL36mULmRFPA9C31MWRJ5iaBNsaABiWE3ht6Ta87UbyCmmnkCVLF63\
          GGYcmpn5iVqX5kKHMvijJ8wt5RL5KzrQqp8qkBRUGXLBhKKaVQuVdCYVuHA6FSnr",
      },
    ],
  },
  Vector {
    txid: "b47475333e88cce58b892189734d9ed1f43af26d09984f7523b30d54d69d47c8",
    tx:
      "020002020010dde1cf04d0a1088d9912f3da0259ba0981029d0bba02dd10c1018501a8045c6040becb2e1ec36f\
      69a4366e256c2dae491c033e1a4aa4de309f3d269c04c3fde7b2020010d3bbe804eb75fdb403ce16b21a8803e7029\
      f058a02a9018601483651748b013b40e3afe8d438edd164cf93358ae68208ad3cd4ce6716d7a2ed29a0c38054e903\
      00035d2db5cab88eab2c440b32fa5c705e140a37c0249145d24a8b2e0329799a426fc100039f3746a4e5aea17f77a\
      d1bdd928b0fa453c907a8b9eb72058f58116c4545a077e90003af4de186f5b9c7b554a347ebe3c19e6f879449012a\
      bab1165a7f48dabcfa1ff2f68301017f6477daa3f99a51ba7e8ebd587d8d2554d175e15f6b5ff7726ff7c6b24c054\
      504033ab5e8bf22b699ed9658d6a5ffca07bbcbcb1916cdbbf8e9409a7ca029a6f84902f26c03dd3727b12062bacb\
      950f0051fe514d4b4d8b9e1ff32a7d859c0bb494f5feeb33802800fbd96ec36b9ef48544ea548cc142ff4f10090d8\
      0f32f8e2b4f0680c1c01b079e42182b525b4b8ad43b24be947065410741194a8118e380ae0037aa85b28ae0270c5f\
      4f4c382e6cbf271d39adb4c96b750212423aa3be540f526ead3e4934d3f659b91ae2d0bec65e046e1ec2c86363c0d\
      638b16645248875bb82742a1308d93f1d1dc44e42d8f2dcfcbfb2a4ed37978d825557a62015015b42284952a6be78\
      817b96069959f0329db483750199e9d99233c451243307f5a83cb34b4d46b7af4350ab29be47935ab1d6c5471e1c1\
      5d7199265dadd38548cb2cbf70cc01097f40a8ba0ce004c8af3cc5c1ba8bf9ffa67078ad834185c5815079f3524fb\
      5613ee7b9200301db1adb15bd6c6d3a19d0a4204afd1256a5705052e1fff64a2af75dc37f0c964eafdad6d2431b86\
      a832348ac551b683f5a291c08663640d5dc33457456eb5a9b88965b68ec3c3d87ee75a08e8bb6accab7af86030866\
      b170c2bf69bdaf7587d88cd72c05f69dea761cc63ea804cf7e648467d13d107a43ba814f5340623e3c9db1eba07df\
      26c5a677d1e9841963a7aed08caf61d4b41e9f063d305c17f7fb75438ff353dd95118c92ba71b13e9bdffbc1af357\
      51c2fc6f5e672589640e3497fc52c446a9d2dd57063d21e2591a0aeeafa6225c3f6f1c4fd5656c7a513f675f6b628\
      5ce57d30eed114ac95770c95bda791d2c442547c5ab7e18a28162d51772644cbac06b9d1dc733bace4102a7022392\
      57b0f2d632a72a2d70c994ea6dd24c3f6e4fe152378dbd509320bc53e642a25a5df85c56e9ecda0a074b93124f839\
      17471a44e9356ec377d6e22ab674435e251053237a741089b934a0627f9a81633e1732330a9c9f8cc97af4c7d7544\
      a0fad65e0fea8701e5ffc7b98002f66d8746dd7c928307aba0608f0db718b7f148baec1721f24a3d47b8e1a99c01f\
      777bb8f7027021972e774cda6ad9b30149dc025ac32b0d8f725fbfe82c518c25a04f404a978cacfdf3ab6c6c70cc3\
      fa47734996bf4fed58dcc2972a217dd47653fb2d6ab8c7325e0d530f17e5076c911d6f447b5e6e0a5ae229ac1b06c\
      dd28995499b87ab5aa35c9a19d8eff1aeaf51545937c151fb0336629a50896485b0c21159a5d0478998b4b7358e29\
      4c3be730b362c073834c8d62184934ceb9bcad384ac3561ec1ad9492392eb37525cc5fa1c81be2bf201932d3a42e1\
      0f5d1f2b0bb4f00e88a2f7206cb55f9c522ec68ccb6bd5615652d4ed3c011ab02b52b28875801d38a0c5566336b21\
      859e7ce44711fc56fb7ce65986fae1c9840d72ffee420c92cbfd7a395b279077b6c8315715da1fd3ff56d5d68fc00\
      56270067d854f5ee62b50e8e9ae79e5e7f3f48c1f2d161449c42ce424e2f3b0084afe01f40fc5441173a502aebf94\
      b8093be53e50e0778ed5d471327d4a3b8b56280f0ca1419b11580997bee41a6686935c31eb82cb13da37fe332427e\
      60777fffbc3039cb6190680c02dc5b038cbb46fa426b2414659679284631ca6a95249169f240803c1dd7e340ce47f\
      e109a6b43076738f8fcfb43a1639163cf3b83ecac681ea0e399a5080d7ed9cab6beccc9f99bfcb4f514d37e977199\
      7d1a53dd7dd6f0b4801165f05b2d07a51969c5fe47703035f659a0d51587d5cbff67b657d7047811203ac5a7931dd\
      135fcf4a415ebf9b8f4a90ef3c777773ae58c7bdeb2b42b5ff3e0caa7527f92fd71ac8f46b193cd1bc63a4ae0d0dc\
      70b27bb6933f97671b5a99a0fbd65fe6d5d3cdc2ebfa7fc9f82f127af8a4fdad0abfeee27d68f3984661a3309c5a3\
      d367f43f8d151fe1128e39df1f0481750a7ab4f5bef29a9899321df6db06c10ea7a0c6c7bb6cf2d47a0198255b839\
      6f6c407db6ae1c4b87efa3f45ad0a0f3f84cf0844d18aafa78ec1bd4235ad41f1bbbe1cc89127aa8891eecc233c5c\
      0fb0c551a24a5e2369890d54cd4146d444da9e2561edbf63dd6cd6a73031c37807d04a98dd8af150a99b09852e041\
      f9fd581c7d2ae376558653b165a25a1103ea983bda77cad30227ef5c4b13ddf254e515f2356e1c89f127cd42c8d87\
      edd5da0839762be6fad054e35cc8fc1615694e9cdd0c35060c5768cefc6c634f88e7f607eec51b8333377d0cfab66\
      ee1d0ff1d3bc45899a6be73cc82ff90e310a310e009aeb68f5b8e2292e6bacc7092e755f03a01de93d484fb6522be\
      9ea5675300cf00ab00faf720f57bf0eaed6d39d7cc62d55dd6d8ef25f4a41414c83d2148161807b54f1fa07ab512b\
      c065bd1d5ef15f8840fd3aca12c3398a8f7ae379abf66c202877da809ed587875629757aad4f80873e61c2081d79c\
      e6ce0eab6d06735db4077b00fe1e7b3c1499b931403d11aa3765d8bdbedc00eb367fbfa0664cf584180c8e3d28b3b\
      c9fbf44b0ba5ae93e1a3d8496a924bafc6194535d1a73c78517c00cb6a1b37d335c54b003ce223892898ceec9384f\
      bf42c0ce5804a3c08cbef44d00aed583566e3d19e22f32c4833f604a3b82c9502ad17e4a1d4261a1893a9b9502b15\
      100a50303d2c1d295681cc435e42cefd12a7db96fb7b8fada76b02b19b40ec885e2b15f20146687e97a02ba09f2ec\
      b9bdf695345f8adf724db46d89aa7103378056862452d6d351407f6cdecb97d585d72f95b9702524f3867f853a23a\
      60d5b7410cb07ae4d0403f51b9fc1fbee1a06b89ded83e2e034c9f36034e939cc0b9f5dd5275c8f8628026adac5fb\
      ebe36293630af1fb92bae40f6935d96f6f1a096cf3a291fbae981930930e734fda973e4df468d8595d78a9929b21a\
      68b22890d0ba891d47386571148029f307a320dfbf125eef2dddaa5b515f6aea9eb2584cc67f41efa44a9f100345c\
      22ac8d9d4c2dffe3fbf6b061236a4d1520de37f8daa5fa02285fa815117d2ac7984d94f00884abc4b80129412fb95\
      b1926dbd1fbf05e",
    tx_keys:
      "835d658e6c42914676f5795474157ccfc3bee60a45c143b0b2af8615cbb9010a0aa3f18b6c3fdef7a4c34\
      94ebaa0f9af67d7eaf12b716f6840310568f8f0f30d8a03af0b759d7c54a8712f490363bdd13a56523be0859bef62\
      24fc60003aa402bdff760dd6b176ce9fa63acf05736ff16cde97542f428e8cabc69c859d9b5701",
    payments: &[
      Payment {
        address:
          "7BnERTpvL5MbCLtj5n9No7J5oE5hHiB3tVCK5cjSvCsYWD2WRJLFuWeKTLiXo5QJqt2ZwUaLy2Vh1Ad51\
          K7FNgqcHgjW85o",
        received: 23_400_000_000,
        wallet2_proof:
          "OutProofV26dhpdcaRNo7SgRCtnykvTyfnKJfC633cn8G7SKUcje86XNoH1rwfraJTWWnNE7aR3\
          aEu5m3g9JirvAuaA12G3pJn7bMabCnUYHzaXkmHcc3zhEV5Ybp1UkNtJKdNWXB4uBPQ99cjQEkL8hgPQpdaH3qw69\
          Htwses9UKvsjaPA4KNVFYqJ9CGgbNu5543jGC4fu2VAnWKKkScJYuozRpTS8QZ7t6iQuGu9uLLVhdSmDqQAYu22M4\
          LdBmEKiFtSKPJ8fMBdkUbhEjkJ3a9Q3cDZBC4a1WkiUDLGx3D4d78c618nqbn9BaoSSyKXvtLCXKRvDWatZhsTF3c\
          ovmvaM8WFKmF9TMoha6g7AsBxJjg1TxUC2GMF82qeaXh7P6XEzdFeKwSb5mBoxJVMZxJR5u3uCY7odccjKByGf4P8\
          D3RpLgkBGvDeUsrG44JW9JHrxenXBrLuXNpFvSgLPPSYUgFo4ZghLon8B54LW2Qbt1gbagFf5NepsYmyS7vUkD6qv\
          2oEnpDb8iQ3MK3xrrP",
        rust_proof:
          "OutProofV26dhpdcaRNo7SgRCtnykvTyfnKJfC633cn8G7SKUcje86c3jr9z9UFsr5V8xsMwW8giYY\
          6rv3u8z5Fc1TMaBsr69z9t8tztwqF2Ffipw4nC7Xp7MEjfXje2LHvXMi4YuoNzEr99cjQEkL8hgPQpdaH3qw69Htw\
          ses9UKvsjaPA4KNVFYqdbSDfwa45w4eaVTSNZokqxbhxuogDCgKa1RSiyZujRiJ4aCL3wXF8FjW7WJDMP67fVaMrL\
          YNP4znTURf3MAnQGXNhEjkJ3a9Q3cDZBC4a1WkiUDLGx3D4d78c618nqbn9Bao85EMKWX3NrqDN2vDykGqBJJrQwo\
          jG784e43X73cTLAuBMapuqbEVQpNh3K2x1Y7yxhQSUqmx9SdwQMqB8LQ3rUkRMZxJR5u3uCY7odccjKByGf4P8D3R\
          pLgkBGvDeUsrG44JfcypsjHN5digAL7wsiChG87YwnVK38cxKcsLfwq6tBuEd3nAkowfSV9C3mGqJbjMuK7SsP98U\
          PCcT9XENhb3Vave",
      },
      Payment {
        address:
          "55LTR8KniP4LQGJSPtbYDacR7dz8RBFnsfAKMaMuwUNYX6aQbBcovzDPyrQF9KXF9tVU6Xk3K8no1Bywn\
          JX6GvZX8yJsXvt",
        received: 5_600_000_000,
        wallet2_proof:
          "OutProofV2FbWfRLoRk5cWHR55aVVYD99KvBkgCf8TFNou6Dhr6J3TFmxjHmPA3kTFAdoYxCSRH\
          q5CtcmKcnS721ips9PkEt74Lkrd6gX3wvhg1h9cvShoPmGSKZmPrVPBrBZAqKnVb1wZLinQF3wQrfNfivaDG47N24\
          DyQP4A6akjudQ8dvZsu8cUJAydRjLXJXpQQ83KbDDKrb5kiYWqdNY9pWz5uWJAQvsyZnaGn7HX9kJGnU97MAQsoN2\
          43tH98Nki4VQpNXPEinpNWKDHX57wnJvckwLB7CyoTYUZTL62oEANdJ3PYKPzNcgyfNHk8YLNRB29r4t8Ma9sdHWB\
          DNcazHLCuN4v8BqXBkM4aDbNY8Xc3tC5n4AVtWRqgvYrvw9h1HL7veMmXGfG2e1wbjPgQBB4i9uEvfqngERYUj5NL\
          DJQc64qzARpiuZG5iCbE1W6n81KreqZnqSDmWnjuP651p614rDXQ4zxaZ77PV5WaHfwtNJLa5dPYQeFBKpBqn54o8\
          EDBgvRZik6cfbTwqTK",
        rust_proof:
          "OutProofV2FbWfRLoRk5cWHR55aVVYD99KvBkgCf8TFNou6Dhr6J3T8JVNE1VNijygHBrkawvbA6eN\
          ZKgJ2FZYMg9uA86ep24sfziu7npPD2VGD5MB6dDxXbWJvTEAAdmZHbddivbPuzVdLinQF3wQrfNfivaDG47N24DyQ\
          P4A6akjudQ8dvZsu8cUaLHFiBacyKNTL1mqxm3SWjZWJQPx2CnnMbYhhbWUT4UZcYGihawCm3vWWuBXXzjSvGFdu1\
          f5XBzHbVp2HbMsboveWKDHX57wnJvckwLB7CyoTYUZTL62oEANdJ3PYKPzNcgyKNdpWQtTpnZXafVc4Ufe78f2uME\
          1TRks3HqhbGkLVP8dNRVbKxF1UfK8Z9p49YVi9hAkricYyuSJJh2EQrYwqgj1bjPgQBB4i9uEvfqngERYUj5NLDJQ\
          c64qzARpiuZG5iCb1E2Aznq3RufMLGH3hAKPc1jaF7YBr7W7UUoTVCXx9wUf98Tg64PJm4VBf8Y2tU9SW89y8sRdc\
          86wwhbNfHomuhDA",
      },
    ],
  },
];

struct Payment {
  address: &'static str,
  received: u64,
  wallet2_proof: &'static str,
  rust_proof: &'static str,
}

struct Vector {
  txid: &'static str,
  tx: &'static str,
  tx_keys: &'static str,
  payments: &'static [Payment],
}

fn transaction(vector: &Vector) -> (Transaction, Vec<u8>) {
  let tx = Transaction::read(&mut hex::decode(vector.tx).unwrap().as_slice()).unwrap();
  assert_eq!(hex::encode(tx.hash()), vector.txid);
  let message = [tx.hash().as_slice(), MESSAGE.as_bytes()].concat();
  (tx, message)
}

fn tx_keys(tx: &Transaction) -> Vec<EdwardsPoint> {
  let extra = Extra::read(&mut tx.prefix().extra.as_slice()).unwrap();
  let (keys, additional) = extra.keys().unwrap();
  keys.into_iter().take(1).chain(additional.unwrap_or_default()).map(Point::into).collect()
}

fn received(proofs: &[OutProof], tx: &Transaction, address: &MoneroAddress, message: &[u8]) -> u64 {
  (0 .. tx.prefix().outputs.len())
    .filter_map(|i| proofs.iter().find_map(|proof| proof.verify(tx, i, address, message)))
    .sum()
}

fn prove(vector: &Vector, address: &MoneroAddress, message: &[u8]) -> Vec<OutProof> {
  hex::decode(vector.tx_keys)
    .unwrap()
    .chunks(32)
    .map(|key| {
      let key = Zeroizing::new(Scalar::from_canonical_bytes(key.try_into().unwrap()).unwrap());
      OutProof::prove(&mut OsRng, address, &key, message)
    })
    .collect()
}

fn shared_secrets(encoded: &str) -> Vec<&str> {
  let encoded = encoded.strip_prefix("OutProofV2").unwrap();
  (0 .. encoded.len()).step_by(44 + 88).map(|i| encoded.get(i .. (i + 44)).unwrap()).collect()
}

#[test]
fn verifies_wallet2_and_recorded_rust_proofs() {
  for vector in VECTORS {
    let (tx, message) = transaction(vector);
    let other_message = [message.as_slice(), b"8"].concat();
    let keys = tx_keys(&tx);
    for payment in vector.payments {
      let address = MoneroAddress::from_str(Network::Stagenet, payment.address).unwrap();
      for encoded in [payment.wallet2_proof, payment.rust_proof] {
        let proofs = OutProof::read(encoded).unwrap();
        assert_eq!(proofs.len(), keys.len());
        assert_eq!(received(&proofs, &tx, &address, &message), payment.received);
        assert_eq!(received(&proofs, &tx, &address, &other_message), 0);

        let signed = |message: &[u8]| {
          proofs
            .iter()
            .zip(&keys)
            .any(|(proof, key)| proof.verify_signature(&address, message, *key))
        };
        assert!(signed(&message));
        assert!(!signed(&other_message));
      }
    }
  }
}

#[test]
fn proofs_from_the_tx_keys_match_wallet2() {
  for vector in VECTORS {
    let (tx, message) = transaction(vector);
    for payment in vector.payments {
      let address = MoneroAddress::from_str(Network::Stagenet, payment.address).unwrap();
      let proofs = prove(vector, &address, &message);
      assert_eq!(received(&proofs, &tx, &address, &message), payment.received);
      assert_eq!(
        shared_secrets(&OutProof::serialize(&proofs)),
        shared_secrets(payment.wallet2_proof)
      );
    }
  }
}

#[test]
#[ignore = "prints fresh proofs for check_tx_proof"]
fn emit_proofs_for_wallet2() {
  for vector in VECTORS {
    let (_, message) = transaction(vector);
    for payment in vector.payments {
      let address = MoneroAddress::from_str(Network::Stagenet, payment.address).unwrap();
      let proofs = OutProof::serialize(&prove(vector, &address, &message));
      println!("{} {} {proofs}", vector.txid, payment.address);
    }
  }
}
