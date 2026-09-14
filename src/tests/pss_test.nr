use crate::types::{
    Params1024, Params1025, Params1964, Params2048, Params4096, RBN1024, RBN1025, RBN1964, RBN2048,
    RBN4096,
};

use crate::pss::{verify_sha1_pss, verify_sha384_pss, verify_sha512_pss};
// verify_sha256_pss is imported through the backward-compatible `noir_rsa::rsa::*`
// re-export path so that path stays covered by the test suite.
use crate::rsa::verify_sha256_pss;

use bignum::params::BigNumParams;
use bignum::RuntimeBigNum;

use sha1::sha1;
use sha512::{sha384, sha512};

#[test]
fn test_verify_sha256_pss_2048() {
    let sha256_hash: [u8; 32] = sha256::sha256_var("Hello World! This is Noir-RSA".as_bytes(), 29);
    let params: Params2048 = BigNumParams::new(
        false,
        [
            0xb2cae9b4d726643aef459696fb80d7,
            0x46585d789783e6f0ea6a4a17001b8e,
            0xfdf7476659c117564ca991f3d635f4,
            0x9bb5835a63f78d2ff06927d5f5a64d,
            0x18ce92c21c9a7dad5ed41c66790811,
            0x38003b2699273864cc87b363714855,
            0x7c19d41f8dbe41e03505fe1e061a5a,
            0xd63a7a6d91625495e46db9161b0d7c,
            0x3dffb1f7121946f6e04dc642a85da9,
            0x389eabe29dbf38c1be95c9b9c0c029,
            0x77a14dc6452603a154cc463e4c2a3a,
            0x68eaeef1963fa3866c934d1225ac67,
            0x3a66b9b64048ed95cec6bbe4235189,
            0x113fd1c23822a8dd63e7d97b034eeb,
            0x28b7376afc6109602ed94eb40284f6,
            0x4d331f4da82c798979e7d9d2c5f7bf,
            0x716d8b401bea115cf1265f976aaccf,
            0xaf,
        ],
        [
            0xe67a936b1d351d5e9e8a55ad6c124d,
            0x553102694f3a35c3cd6f842e534a10,
            0xb934cc00cb54a99799bd53e78247d2,
            0xd48adb2a502ff144cee3f5df292f23,
            0xd2170b1ab2536010716815b69e52d,
            0x9192493ce8a2ac8f17fe8124f777b9,
            0x3f8fc6f1a8278440eb2ed4eb2fdbc6,
            0x791d65e427a1b05a2d5d2330227386,
            0x21adad378aa9e1b851343bd555b0c1,
            0xd16a76764fef83357cb77288c59923,
            0x7b6ac8ca2c2d8e501fe71dce81b173,
            0xd87538a1f031aa5a7d77b3f40dba95,
            0x51e193d1f92734383b0d3c482e8292,
            0xfaaa53de66c9dbbda9e43ad85c8b53,
            0x7063684d060473b9779bddbb468618,
            0x7bc190769f2b03116e9d350d56fbe9,
            0xec116198c3a4ba97b3a3976d172ba9,
            0x5d62,
        ],
    );
    let signature: RBN2048 = RuntimeBigNum {
        params,
        limbs: [
            0x6d3125fde00a57fb5971460c38a826,
            0xba2092dd58c4de8ffff2bf13f5ef57,
            0xf0ad4ed46727881e7e7f6a103d7713,
            0x7e8b2203a7a6e3a3a30219d6edf8a2,
            0x9b0b861dd1cb2751f30d54d07ad167,
            0x4373e863b15edba97439182a6a9043,
            0x61621211db5f34a0786d5ef38cd90c,
            0x63001609f7dffdc70761c67617b580,
            0x8b2b817a0508e4be6f2c50df23962d,
            0x6d6f9396978782a90fe06ca78c4f88,
            0xc567a9fe5f7175225384d7c1e4c991,
            0x38926dfee8636b9e36728c1cf51198,
            0x0eb84e90f89a0bd21536a537618b92,
            0x23dbdcda1fee2b57c8dc2e605777b7,
            0x6acac69b2fc1c12c204e790034a01e,
            0xee44b77264385863ccef2e133241cd,
            0xe9c67049c219997cc8c43b0b1f420b,
            0x78,
        ],
    };
    assert(verify_sha256_pss(sha256_hash, signature, 65537, 32));
}

#[test]
fn test_verify_sha384_pss_2048() {
    let sha384_hash: [u8; 48] = sha384::sha384_var(BoundedVec::from_parts(
        "Hello World! This is Noir-RSA".as_bytes(),
        29,
    ));
    let params: Params2048 = BigNumParams::new(
        false,
        [
            0xc3034c17b5578d9c029b22158a8e45,
            0xa84c80b43a68c9eb7cde67f1f60e07,
            0xa8d82a4aef2cd733a9fdf43439ffbb,
            0xa1b9aae31832c2815b81f0db70962e,
            0xcfcbc51338d691443e702bd18354a7,
            0xaa2c5f465a247efc9d97fb052579b8,
            0x571f3c233fa322a933a4cfc0c4b213,
            0x3280f1f7238a3416c5e1140077537a,
            0x8685f03e3076c1bb62550cb363ae08,
            0x55ebdcb84073ad2dfd3553c5e2d21a,
            0x1e5a0a662b44f5250377abcd1069e6,
            0x178357493184215e38603004f6c9f3,
            0x75cb8889b33c6b78bab0a378453376,
            0x4f5f7baa56492d5ac52c1bf7b998b,
            0x16cf48a7c416bbf67657a263376e22,
            0x1d8ab41c7021ebcb15da705dab5343,
            0xc5e43d48377059df0aa5d7e5441586,
            0xc7,
        ],
        [
            0xc8694aa1f2a0898fa5bf5b4afcd05e,
            0xd2ff5d0abdc00837c07db2ba581e4d,
            0x4247b72b504736ff0952eecaaca419,
            0x7468a546a39437a7242e00f0f524c4,
            0x41ab45d8341ad49c233303b67f98a6,
            0x46e5899941698948fe73e84406a721,
            0xf9490ec3cc3b824310607867d17c68,
            0x8a95bb6bb23e7f84b5341f5c964c7a,
            0x41c8ede03dfbc60e4c0c73b53c5226,
            0x7bdf63716d59f6c2c6996dd15897c9,
            0xe7cded7bfaa6a4c0a75f577689af08,
            0xd6491f3fd55c32e41d6b83a2d73fbb,
            0xecb9b002d3383fbb7103cd8cf4d539,
            0x24146b53e44b9e95d4f98536248c83,
            0xf3de3614bd7ddaf099ec3af3c4f0e7,
            0xecf2cb7c98668c083c82037555595c,
            0x5927980c9617d08942b1b254447025,
            0x5203,
        ],
    );
    let signature: RBN2048 = RuntimeBigNum {
        params,
        limbs: [
            0x06d24f9dbd859780c7684e7733ebb1,
            0x3acb7e4bd7c9f42a5f9649e1fef5c4,
            0x67878f2493de5cb48ae107df08dbf1,
            0xf268bc940d64e42b8719216fef188e,
            0x2c4701120db41532e6d195ba1f8faa,
            0x03d3b537eefd6f0c99fbb7c1f359d9,
            0x35b732ca45b03bb17b1f3564f18464,
            0x468584d7dac0a4ba51032e2a5f95e2,
            0xe10042eb30d1662517aed3b89e1154,
            0x0e5743acb366c6251627e64f751256,
            0xb06e6af3e06ed5c656e66aa0295f63,
            0x67378aabfe17e33e305825eb4f6c5a,
            0x8cd4c7aa81b660325dba4b0d899a9c,
            0x40c83a9c74f99c026aa845fa222b69,
            0xd52f8e19032a33a1d9a01063fff8f9,
            0x7dc36972054edf46bbfe918711e693,
            0xb035fca3baf4329ff5d588baf7b034,
            0x1c,
        ],
    };

    assert(verify_sha384_pss(sha384_hash, signature, 65537, 48));
}

#[test]
fn test_verify_sha512_pss_2048() {
    let sha512_hash: [u8; 64] = sha512::sha512_var(BoundedVec::from_parts(
        "Hello World! This is Noir-RSA".as_bytes(),
        29,
    ));
    let params: Params2048 = BigNumParams::new(
        false,
        [
            0x928a173c3947c058b084e258b8a4c1,
            0x5f1179c22cfacb440464695cfa393e,
            0xc409e532b3077ce4d90e66e913f125,
            0x29e8696374f86380ff45d0f29a98d5,
            0xf931d155d89d3753ee931433a8e2fd,
            0xfc3d1c2a999f0112f5c5416c2e0428,
            0x4d21692b210bec2ab8e1b52fe78e66,
            0x9df364fad350d314b146e84f114203,
            0x8511a74031596831dda8ac9d18dcf7,
            0xab5f9ad71b33284aae738988284229,
            0x3332aa31681f69a5f470caadad7469,
            0xf1fcad281e0fea144e1f4208d38e38,
            0xe83d3b0afb20bc39814ea22df000ef,
            0x3d9244664808f54fc4f0702adc9399,
            0xc087b5dc693953e6371b9c7c175a21,
            0xd5910d0d4232e8f92148482a72baec,
            0x44e57b58ec4e75250116ce2f1abf3b,
            0xd2,
        ],
        [
            0xd2cfd3241c49698541526e2d68e1fa,
            0x70bb32660757f09fd69a9ed3c8dd59,
            0x5fb8653b112d29137c662027e359ce,
            0xffea687b1f66a6e45786af1d7124fd,
            0x78ce565b09f264c4d69fb84cb3ddd1,
            0xf6de225474dddebba9abfb85c6d5a7,
            0x376a4c49a5c09c3b50ab9817a6093f,
            0xfe9b81ed10a7c3ba0dc3262154fb8e,
            0x9b65790fb47865828c5bbafdacec2c,
            0xf4556e409745bb36f6b1cdc9766a24,
            0xbd691c41fb00ec17d6843ee93e877f,
            0x86914a171770cd55d05c4f5b5c6890,
            0x1913c7d1b3b3600f94c444368ef57d,
            0xbe62755b1504afb99662bc960a5c8e,
            0x4bde09fdebb914fe70fae5d4fef92e,
            0x7ce35bd7c68ffc350318075e676ec1,
            0x5006f45883f7481904ea25df798dd6,
            0x4deb,
        ],
    );
    let signature: RBN2048 = RuntimeBigNum {
        params,
        limbs: [
            0x2058f7115f339e55a93f8dcefe81b9,
            0x38a20cdbfc439a1fea423c119f2879,
            0x7ac4e03a5fa662754e6e21a78984d4,
            0x69d714829d29b235d588476152b5af,
            0xce3db2102990c27bb66bc32da8dec4,
            0xb4914f6f0e73718b5f1e422fac6ddf,
            0x7d812b554c81ccb7932d1e78c6e002,
            0x438fe60d9e0912328374513ab91b69,
            0x56abaf2b8d9a6dcb9201586d2f0d0a,
            0x4151c524481066bd81b4cd17829481,
            0x7c63b445e245d09ca91057032ad22b,
            0x9f242d5a655035a028a68d337ae40d,
            0xb5f91b99b495862044bc7122913806,
            0xc123aa56dff5b23d7d8ad097748efb,
            0x6892e3a32a7b6963d97b3bdd81b91d,
            0xcd7aa9e3e77f68f0ed195bff92a162,
            0x583a32fd5a399f3acd867dd7d6a1b6,
            0x7f,
        ],
    };

    assert(verify_sha512_pss(sha512_hash, signature, 65537, 64));
}

#[test]
fn test_verify_sha256_pss_4096() {
    let sha256_hash: [u8; 32] = sha256::sha256_var("Hello World! This is Noir-RSA".as_bytes(), 29);
    let params: Params4096 = BigNumParams::new(
        false,
        [
            0xd78653b3d43a72784415fc0537129b,
            0xc725d4fb19419a03b58e0fb5ea4ad2,
            0x1d866cfc050224a0eb317e835ee283,
            0xd298018e86d3225a264a449c63d69d,
            0x824db5365a077bf704acd2446baa7f,
            0x5c419e562b5b5ccb0dcb151a3f48c9,
            0x198a6627edcbc2afce1893217c2e25,
            0x29a693a0bb3f6f02d80e660f681d6d,
            0x5656562a9622f87bfb969db2542f63,
            0xb9408b08a3ee3b25b6dc6ae12899ef,
            0x4ce9b767219e1e0593782ce46a041f,
            0xc5a4f318b34ff79121677f283ceea1,
            0xbd5e62c599453a94e0bf5f48c6b58a,
            0x6ce23c4978ae07af4c46ea9b9964ad,
            0x68d4db6209ac89538e6d986cb77459,
            0xf2ada72cff01696e2efdf123ab60f3,
            0xf951c3c1965c355f460fa815587ed2,
            0x6063ac0275e6592b878d5a66e68501,
            0x594eb3db288ad091bc1db2b2a90101,
            0xb72899c91edcdf890053f87d5b1dab,
            0xdfd45eab0c435e275202bff1e22f5d,
            0x3da05e1d0d3cd0012e6c40e1878ab7,
            0x4fe053feaf486a27dd119cbee9ce1e,
            0xa3781b036bd3a3411c2af8377ad0d9,
            0xdf4410ba8397cbe580fc5eca7d230d,
            0xdc34151036d459fc3c21d8ba0702fc,
            0x4ea71eb1b0b1a2f36741b61e8765d8,
            0x22cb66b4eb0b34b34320402ef652dd,
            0xd19167b88620fc6b60709fd39cd48b,
            0x524e4fbe4d75e4817de075ac70c72f,
            0xd0de26679602cd331c3e5534ce668a,
            0xf5aa120ff51d4bd3d57c1d68359f95,
            0xaa06f0791b623cddd53d787035bd66,
            0x122e014d565fa26417a5ed0f786fbb,
            0xb95e,
        ],
        [
            0x130efdb324cd712edc667e7ad1e975,
            0xef2f9ed6cf3eda5f1addff86a819bf,
            0xfa4daed45b1837b1b9ef7a42950159,
            0xe2a4bb6faa59e8dc3724a2cbd32d4c,
            0x677c25de54b509e39ad31e4acc70e5,
            0xf6253afb61c0ac5631e9477fd40ae2,
            0xb6a4fcdfaaeb76395753d142fd2299,
            0xed66b2eb40ce15af8e22fd66dcf129,
            0x191374cb71dcf9784b80ce036ffc07,
            0x7fd67a2bbedeb3206f78c3dec8a242,
            0x2991b0fdaa6206551fab99dfa659e7,
            0x31ddf5f68162de83622dfb21100298,
            0x1ae942df31342bafe289747ab283b0,
            0xbcb322eaf779d68c621cae54a217eb,
            0xbf246ab7233889fa40e723cc523671,
            0x9ddcfe01088753d6328ef44654af1d,
            0x3d6882bff168266b496aed6e731889,
            0xd82a4423acdb201a3a4f949308d44b,
            0x2d9ebe1d85f736538e298a9ca5d9cf,
            0x958d0fe38600ba3010ec9887d6c236,
            0x60b2386a34f91639e5e69df35d9091,
            0x4afde0f1e1ef8d02f59bee281f475f,
            0x25345b8ba920da7d5eaf296426e073,
            0xbfd10950ad3a412b4f288341bb847f,
            0x87e88159589f75fae5ad009ed9c53c,
            0x4ea0b52137d260f6d7eb75ee4c122a,
            0x17d3a64ec2742ae06e0c4af027c1a7,
            0x344d69b6a988ee41bed8b1b8a3a784,
            0x696af95957d8a828343651e6b9d9d7,
            0x33ea26b6e822e491c97250295ab678,
            0x808ec74c24dbae7b952fde2409b888,
            0x27a47c46a89a7ce0448994f1c13355,
            0x845ba5db5649cdf8315f70489a7bf0,
            0x3a228c80a826f7aa8f6da6be629944,
            0x5862f8,
        ],
    );
    let signature: RBN4096 = RuntimeBigNum {
        params,
        limbs: [
            0x5d9212d0c25acc14b61c6ce61a844e,
            0x9d369ae765eb0545f83f552b8d7bb6,
            0x5f0f5d383bd70d7726a851c422fe29,
            0xcff5886575636efcde5d9843e59a10,
            0x5820fa1e3158154641adb2c28a8954,
            0x03ce0301512be13c0317fb679e6348,
            0x13ec0af966303ca69b6f7fece6c2f4,
            0x58dcc592b80e4756a8d01224e6174f,
            0x73610ba199750de1e35cd658cbae92,
            0xeb1d49f1ecc3bf332b4048d978a46a,
            0x8c9ad13691accdce88ce1e6fda0bf5,
            0x425e80441351444e751cd86b97b464,
            0xd25a9581921c44fba102ed92a75658,
            0x698c73a7fc85fee22b1c7f04fb4600,
            0x70267fc50db236dfcf1e9405e25856,
            0x1a35b94cf56f801be96defed712afe,
            0xa3ecae6965b3bdee416f8d506f64fd,
            0xc875faf0fb4e4fa47ff65aba633529,
            0x3ca01bcaf3c4a5eee7fa8fdf0e98,
            0xa666b5d8c9f3217c412610ae91c862,
            0x517ccc77102fa7799e521ef0e6d4e7,
            0x7a50f7e553db75f0e0bd18d43bd622,
            0x98e8da14444b6cf3d2b91d84da3506,
            0xd1f5e4f7a725babc988cc7822c3d0a,
            0x09ee2caa2e6f8b02db37ebe2352624,
            0xd500b790312328a681b89b5de51b4f,
            0x5ce0ebb445d4c82c3ecf21134c00bf,
            0x83b6fafae79bc59f07e9b6802ef018,
            0x8efd78556c637f8af6299ace0cd790,
            0x5e99cf54d0f7e491cd72bcf20701fe,
            0x19f15da137fe1bbe44c5531300829a,
            0x0aae159f54317b49ec6b083292f57e,
            0x37c2bba2237a59a35556f2d351c728,
            0x7ec51821f03bde0c862e19e6ebe62c,
            0x2081,
        ],
    };

    assert(verify_sha256_pss(sha256_hash, signature, 65537, 32));
}

#[test]
fn test_verify_sha256_pss_2048_exponent_3() {
    let sha256_hash: [u8; 32] = sha256::sha256_var("Hello World! This is Noir-RSA".as_bytes(), 29);
    let params: Params2048 = BigNumParams::new(
        false,
        [
            0x1c961b234309c24fdab3f3e8a09da1,
            0xf4aa851a30a198c359f3779b6bf4e0,
            0x844034a1488c79edf31b1711a5e547,
            0xc83ad2f9b30cfcb6d5f7c152a78e62,
            0x16e97e0f8d8bad08da76d859c575c6,
            0x6a85158069b211820a596359d0dc47,
            0x1b834ed69818f1aa7d9944dee07b20,
            0x4d7148da361f1881cd4fd396ef46d2,
            0xc4cf36bbfa2781703699abf19a1e6d,
            0xca4bd632c8eb2c8051915c3530aef9,
            0x9cbfd5681aa95ade8eb256925d60ea,
            0x3b8153585ff5f1d7b1ed37ac709dc6,
            0x7d741c118fd653af3c21848f789ed8,
            0x7aefa65093c124e46405849ca82ad1,
            0xf9dbb9414e8eb849e2532d3f55d0b9,
            0x35aeee862ac76c20be58527220f6a,
            0xa3b6f81f07963c34ff0168634f8a99,
            0xc4,
        ],
        [
            0xbe38b5d269659ae63fe843a81c7505,
            0xdc12c3be2b9c78fc69f49361c555a,
            0xa40ef90a16716f572ee4d74425fee,
            0x6f713878999c3b5cd6038b23051306,
            0x3945e3fdc067129b0289d0eacbeb85,
            0xf66e9cd953b3c8082f7e9bb6771ddf,
            0x6ea578f9d547b898693c43b28d7c17,
            0x7826dc49d3977c4381a9b398c670fe,
            0xc51e07beb646f82223d4541dc7ba96,
            0x574bd2435ae8f3c96b64797894e6c2,
            0xe21eb28f7c865336fb64139b50a5dc,
            0xde5fc8600a814b047970816f2df485,
            0x53456cd7abd1b8bf9a7cad8300a48a,
            0xce053c7458041e8ffc4206c3347faa,
            0xa930c6d860e7106602a2ee7248a831,
            0x48f327c2b421d1d4a45c68b8a1bada,
            0xea2d963f93a6d1237afc8763a83300,
            0x5351,
        ],
    );
    let signature: RBN2048 = RuntimeBigNum {
        params,
        limbs: [
            0x091a8c417287e046ec96c62b5ac66f,
            0xbe71db0fe3122ea5624e8e7a0a72dc,
            0xf35e5f3537c0ad0e938fdedd454de9,
            0xd53c652cc3aac5d11fe6f5bc7ec536,
            0x5d6869f0dd8b00697743f956b9b112,
            0x5d46286274a1128a8fe0d96e859837,
            0x951ee9dcb59dacebba972e9b9d7cfd,
            0xd22245a462bff840a882f6869689a5,
            0xcf7605b64a20dc2c3e6d5ceb88a03a,
            0x7831aa25052c11411c3e5bdbe7dc10,
            0x8e3bce799814987c984a2cc0e5d283,
            0x7fdb0ce6e413e0f32742f4652f14a2,
            0xa896a360bd70243209390e00761c57,
            0x0d326051ac677371678f92bd182f13,
            0xfcc593faaa9f45448ab756d70def,
            0x2fd6d46ec8d25a6648dadf8246daf0,
            0xe4aea2700222e610c1d94d82dd0f52,
            0x9b,
        ],
    };

    assert(verify_sha256_pss(sha256_hash, signature, 3, 32));
}

// Test an unusual key length that is not a multiple of 8
#[test]
fn test_verify_sha256_pss_1964() {
    let sha256_hash: [u8; 32] = sha256::sha256_var("Hello World! This is Noir-RSA".as_bytes(), 29);
    let params: Params1964 = BigNumParams::new(
        false,
        [
            0x75ac0d9987aebebd25983ab5a48fdf,
            0xae0a5ffc69f51e789ea8f90a72745b,
            0x9b8c92fb6ea3ca021a894ae52025f1,
            0x50de84cce0d856376083aa1785fd38,
            0xa912e3aabd4191e143128ce89e2086,
            0xcf361d0e7f4fb458b950ca7f58414e,
            0xe27bbefff3820e512b05a07d2d7e1c,
            0x7a2fd42d837098a67f056f1b15ed33,
            0x4ebeddd5d6fde42dc68ba5bb2a3732,
            0x2d1cbcf87c37b430c33b04aa35ce2b,
            0x9e9cd702ef1e7191c78e712ac6e151,
            0x9aef318e4318c313c0cf0c71ba378b,
            0xc1cd2e631f327acf58dca9f4e63bfd,
            0xc828e43ce8acda48fa1fff12de4df4,
            0x2d91364c2a898031a0ea615c82fe50,
            0x3fed935e1e73af131b48aafef030d7,
            0xc278be706ab,
        ],
        [
            0x350d0ee9d50a1df6d2998f04b45673,
            0xdfcfaed7a69f91aaed7e97afafc1a0,
            0xbcaadb1caef7361efcf354d0fdc166,
            0x90dfaba583cab15c53de8d6e00d661,
            0xb806fbb0424112212164cd85758ada,
            0xe5426980135d977e89d4da223c9d5e,
            0x5f6f75563ea20c698ca1276ebb37eb,
            0x9f1009e88ebcbbcc251876c7e558a5,
            0xe228ade031e36a095a4bc73b14157b,
            0x4192b14fb0f1416e3a3896e4d4339c,
            0x4a6c4dd21da8eefe3a0f9748e735a7,
            0xc81b22fd28344595486481f7a646d1,
            0x7f844d41ded6dd834c6f6ff2d3da61,
            0x6c034744336db24703e4fd2c686321,
            0xca48932878f17bd0572c58a7e0b63,
            0xb3283ec30f94ab7f4596efe16cd3ae,
            0x543fb0213861f,
        ],
    );
    let signature: RBN1964 = RuntimeBigNum {
        params,
        limbs: [
            0xbd4bab3d5a9af46cac40fc2f6c9547,
            0xd3e04f0b8e833f1e80a4022684694f,
            0xbb4267e4fc29ec83dc8398dc547fca,
            0xba625b4fdf379883f6ccabede3574a,
            0xc9736193ab3cc0d1ef8ea63fdba46f,
            0x72dc058e8abcbe15ed09e97c1bb58a,
            0x98d8c915cb9447bcce3bbfc0f92032,
            0x9a0778461e9dec09e41c0ea354a41f,
            0xe4a6b80a5f62abf93268cde64b5e9c,
            0xd36dc0ccfdc6d9d8e8a939a3e762d0,
            0x1b2593bff17ff433ee20f1a60c6861,
            0x78115ebfd2484df0b59abfa3222e79,
            0x7693ac9aa8acfb4b5379c0adbcb7d1,
            0xd76979aa97b41f1f58c65ad896f1cf,
            0xe1f7c4fa2dc6cbe0162be9adb01c14,
            0x5f5a8f5b9ca6fe12c4fe3c00795f10,
            0x8b4a98cedd,
        ],
    };

    assert(verify_sha256_pss(sha256_hash, signature, 65537, 32));
}

// Test an edge case where the key length in bytes is greater than the encoded message length
#[test]
fn test_verify_sha256_pss_1025() {
    let sha256_hash: [u8; 32] = sha256::sha256_var("Hello World! This is Noir-RSA".as_bytes(), 29);
    let params: Params1025 = BigNumParams::new(
        false,
        [
            0xf278b138628000b2652c779e852235,
            0x6d0676977e76ef0429002673ce9be2,
            0x6cfc0db4d97f20ad2a1ad48cd899a0,
            0x64024c19a1b1540e23ba4531e677f2,
            0x3696125dd256ffed9567fccff06be6,
            0x2dc09476b0c7629eed3c7c2cb591e3,
            0x2e007f2f978504c5cfea0ec51ba0e9,
            0x84ec9458cc6d0e95e06a7f404f26b4,
            0x174fd186dca48668a,
        ],
        [
            0xeac2318fedbbbb98812f60534c4d2b,
            0x83547154701ba2b91c7310fa1344c5,
            0x7ab0faba08e31b0b0df07396fb101c,
            0x3fd858caf4ba9af077236800aa8315,
            0x707a144de15b129b7230941e2967,
            0x73a3b89232b04b2f0fea909ab3562e,
            0x9c8e12ee0c0aeede28dd9bf18717c1,
            0xba9c5b02995e4cee46cb5222ca73b3,
            0xafb47fe562d6306531,
        ],
    );

    let signature: RBN1025 = RuntimeBigNum {
        params,
        limbs: [
            0xa90e06eff7cbd20dd9c1241fe89290,
            0x9ff719ce8f34229cd248e1f0ef4246,
            0xd1d032dbf236cd711aa4fb49f0c71f,
            0x454abf136ae14c7617df3b4d505e08,
            0x45f30ac2c023205d35803f114f8ee3,
            0xc8b1265c786d6da808ab31d35795a1,
            0x1f75005a85f3636b099c58edd9fb8e,
            0xac251bf9bb342b551c0f5c80449a3f,
            0x03e2bc114292962b,
        ],
    };

    assert(verify_sha256_pss(sha256_hash, signature, 65537, 32));
}

#[test]
fn test_verify_sha1_pss_2048() {
    let sha1_hash: [u8; 20] = sha1::sha1_var(BoundedVec::from_parts(
        "Hello World! This is Noir-RSA".as_bytes(),
        29,
    ));
    let params: Params2048 = BigNumParams::new(
        false,
        [
            0x8076ee27cf6ed266e737de20b03e47,
            0xbd07415cda0752a917b4f40d19c992,
            0xd473ccfa4dc8a5690c17eceab674d4,
            0xdf2645d4e31531b5e68d7b30152182,
            0xe4e6d87d9b3222f56ddc48b46dc544,
            0x587c5d66e6970f42fe18afa99b5e5b,
            0x30261d8162c75fe7ba96ab0c2a6dd3,
            0xdc69073390846c7fb3c98c9c316d60,
            0x4b6a2bc2c1e5131129539c38b0ac3b,
            0xf05187e8d7cf34d2c1685409173080,
            0x2d26be5b0d792a3d92b7d4062b3d44,
            0x4eb7f21f6c4e3df8d2829f6b3e6eaa,
            0x9f1cd4d18bd53d4bbcf804651435f3,
            0x3d266b2f1223e08dd2159d58cb48d4,
            0x873625d48c8244c51924bfdee0c6ac,
            0xfcbf5c61a9d3cf2d0e13686af8d0de,
            0xb4345e8b5be7510698390901722861,
            0xba,
        ],
        [
            0x46d03675a8a2294e5a85be7f217ca9,
            0xf0daa6fd0fff3bb589bc46368eca41,
            0x73fc141cfe4c5e2d626ae4fb73ea76,
            0xbfa2cb047ee7ae250cb3405fb2b8f,
            0xf1d30ac0f7029bbe5cc660879ab6a9,
            0xcd71a546426aa510d9b6397e3d0d7d,
            0x846d473a83a7a76c068600ffe76657,
            0xa58cab8aeffd7b3ec4cd11c5a5daa8,
            0x6b26347dfe5e5b17d0d829b14f02b3,
            0x872b5749f336526ae0ce13984f7c3d,
            0xcc175294f0c4860129f958d98eb064,
            0xbdfe14537208fd73b200a6543d475,
            0x22bc3564a0eb67a33ab75c9d7e5995,
            0x8ddfd4c7ae1178eb9572c7d3c02116,
            0x18f68aa8ef553b722db69ddd898d03,
            0xa4b727519c55d49262a3b69dda80e6,
            0x79319e4fc2f1fd76a017697356ef,
            0x57c1,
        ],
    );
    let signature: RBN2048 = RuntimeBigNum {
        params,
        limbs: [
            0x835c0b9302499888acedea4013ec92,
            0xe1f4b56b2ca0ad8c1ee3b8a9a85d93,
            0x5d4fecc54034eb1091ca9fc28e3ff1,
            0xab316868780469b1621c789b8d8b75,
            0x13205cae60d93b387ef282c901bb,
            0x776e846d321b59b584c6de6ae6da18,
            0x6170c33330baeaee6a3de84e32f031,
            0x3862d9f28a50c32f0f09a6e5e60560,
            0x83e54c8d5a9522e5addc4cb35078b1,
            0xf4cd91425b0b042fb1cbb81d0ce6d6,
            0x33c49780bb4c00637bfd9f5de1d1cc,
            0xcbd14e26c78a769ff0e47854ff9d72,
            0x459db8d780c5287c894d8d419ec583,
            0x19909716db20e09223fbc169d58ed4,
            0x62efd0331023145d761b8568fc93c9,
            0xcac052c722d08645d4ad31464f665a,
            0x33c6a0e25cd27dbfd1d15fc2197aa5,
            0x89,
        ],
    };

    assert(verify_sha1_pss(sha1_hash, signature, 65537, 20));
}

#[test]
fn test_verify_sha256_pss_2048_salt_len_64() {
    let sha256_hash: [u8; 32] = sha256::sha256_var("Hello World! This is Noir-RSA".as_bytes(), 29);
    let params: Params2048 = BigNumParams::new(
        false,
        [
            0x93f3d892703247d5f4bdb3e3864a8f,
            0xeeb6fe2e10ba74b661ede57de66f32,
            0x22651fe330d4c4112b37bdf4b66e50,
            0x95737da8b410591ef8cf9a5147ec82,
            0x36795c89b09d4b2bb1286b3eb02408,
            0xed2fd4e16a15e340c4823ed14d05c0,
            0xf341f7d5db9b59a0cee7b49926df51,
            0xab3d6a418ae21553c0218db4bd539d,
            0x5a44ef24779a5ff840ebecf8954d91,
            0xbea7ac89cee886658623e593beb453,
            0x994b0f172962a7765e45fe554b6249,
            0x992308a3c4f3f47a60f94ebab0241b,
            0x5f282ac7fb2acaf2bec3459ca99ea5,
            0xa0342e2c4c14edb82ca07cfbca5320,
            0xe97df079c947e20f8a709d96271dd6,
            0x9fa5990ee6e97183646e8d22c8e57d,
            0x844dff0cf2b0a2956116138f6e8c86,
            0xcc,
        ],
        [
            0xea31089f1107eb8c25f45673a55ae7,
            0x755c765fac1ef0bb2207d2b30f444d,
            0xafc4a4487e94792b21a48021621f6a,
            0x1c07a280480f453b3c65e5bb6a6a21,
            0x1ea3cc5348312e48a4bf2b727a9d5e,
            0xde15d39c5e7032b06a467c46a0e42c,
            0xe92a1e61a4763dcf93cd8af11103ac,
            0x3153088a6766c7c67a69af85e44c5d,
            0x939e8b17c1378cb0e78c3352e81953,
            0xba0c37026a839e5019aade93a6734d,
            0x4e4532261b27241f4cd9110d1208ab,
            0xb4c1714853298ef242c3459cdae247,
            0x588fb6ed0023bd191e491a48b9017f,
            0xe584ce3c57b7722797ce07a984fc42,
            0x3bff0d3a58afe4dc5b8ccc6c137bb,
            0x7c3a73e8933291f7aa1dcf8e2af90e,
            0x5b921f23c559f2b0b7b5f6fd991c10,
            0x501c,
        ],
    );
    let signature: RBN2048 = RuntimeBigNum {
        params,
        limbs: [
            0x7112edfa6f6fd5bfb0c38c50b10ecf,
            0xfcf8394640dd0c461b31e1139cfce1,
            0xfc63070c16fa641577632dd483f62a,
            0xf80b84f90cddbb6838f7b572ecd8a9,
            0x6db9213f70fa40d11e1ea0b71807e4,
            0x9a1c6f96a7753164bd0402beb70e23,
            0x2cdead0b775f54c33c8b33c73848f2,
            0xf1140865734f5ff9f03c783400824d,
            0x36eb972e53b5acb6c0217d1b470cb8,
            0x5ee60ccd804ebab686b51adbd759be,
            0x4d2349a887d2d707f8c2fe0a53dc83,
            0x86bf074d73c11f919157fe4a05bf49,
            0x0de6169875ea10baf96cf7b53fcdef,
            0x6703f35e54cc01ce5345d216dabea9,
            0xa27e236d8bcc572fc5585ea7289de4,
            0x222c277074191eb0c3b8816813f87d,
            0xf74e23fc27c1df4f43b528b43eb4d9,
            0x43,
        ],
    };

    assert(verify_sha256_pss(sha256_hash, signature, 65537, 64));
}

// Regression test for the SHA-384 out-of-bounds bug: with HASH_LEN = 48 and a
// salt of 64 bytes, M' spans 8 + 48 + 64 = 120 bytes and the salt loop writes up
// to index 119. The old m_prime buffer was [u8; 104], so this case indexed past
// its end. Exercises the largest supported salt (MAX_SALT_LEN) for SHA-384.
#[test]
fn test_verify_sha384_pss_2048_salt_len_64() {
    let sha384_hash: [u8; 48] = sha384::sha384_var(BoundedVec::from_parts(
        "Hello World! This is Noir-RSA".as_bytes(),
        29,
    ));
    let params: Params2048 = BigNumParams::new(
        false,
        [
            0x21a4d8b9514101fa2ee17e07a71df5,
            0x6fb289f941555ed5ef1f9fd614e46b,
            0xcac60cc864fd6895ec3ce241148f5f,
            0xeb23265767677ca203e52a88bd3cb5,
            0x4f61b4845114ffc036653c3579f89e,
            0x6c3bc0e8979dbcace394d8be6cb9d7,
            0x67842a78ef819597771a8f3edc79e6,
            0xe8fc64da9a75a8f59b67d2de00a843,
            0x3c395d9f3c3c9f973fc73b030a9938,
            0x220cacf162f2e6accc16c342ca339,
            0xcde192ced7fd60e567d675c8a608b,
            0xaa1d8fb0766990e0c37c6dc6e2e896,
            0x823fc33e56b85473b91c988957650d,
            0x4a49ee237c039b56663d975cc5d409,
            0x79f8c4b6fc046e2bcbd0247f501c2,
            0x9cc4cb1f92f302ad8c4323681fa17d,
            0xb0d5e3805cb791a1b2f78910112fdd,
            0xe8,
        ],
        [
            0x77ebdfeb81e78c86dcd31236cf9108,
            0x9a7ea8db38dcf54f2233a8cff97b19,
            0x1909c2abb8b5fa57635fe255024233,
            0xc44b159b5067c3face418f1bf8d205,
            0x44e3d04ed352e2c22a7dde425c751e,
            0xf50b99900ad33ad4efef9fabd70841,
            0x5bcde911a0c6cd82b8a2bd1d83118f,
            0xef19810f513268a7f82bf0a86a759a,
            0x4b9b8c155699c6e7eaffedad86c229,
            0xcef690448254d589f98ac47d9a7058,
            0x91efee23187f72225965f17ffa2963,
            0x82e785358733bc27dfbfec6a476a53,
            0x3b3d4a2f43a88d9eaeb7ca7ac8b154,
            0x35ffd752548383c52d950794f84645,
            0xd11483a83839530d4a786f9ec0b67d,
            0xe954e4ad818098a877d3520b346487,
            0x3a4acff2be216d36a1df2f0c834190,
            0x4669,
        ],
    );
    let signature: RBN2048 = RuntimeBigNum {
        params,
        limbs: [
            0x2ca2a2272c7d1803e7d7507efcf5da,
            0xadaa2e041db25df7ae922a35606cb3,
            0x4bb45afe681c20e8c3a7cb795d2761,
            0x5febe0026feabb145e5013b1610d5d,
            0xb9c08a4066b5c1ba4acf895132760d,
            0x2cbd7d3afc3dae066b440e07347db1,
            0xe429b8ca20b05642981ba09346889b,
            0xf6a342ee1c858cb889bf4f9d389852,
            0x40558bb8a7152512e871c06a1f9479,
            0x07288885132093aad7d2725f1041cd,
            0x8f8574fd0ce30d8ccd913f059deb8c,
            0x2265c90599ab52df6aa71efa09b046,
            0x5a980762f5d6ed033d9010332ef529,
            0x16a0a9de71339f9158cf6d44181b7b,
            0x91009e0a6192d08015c551f09de6c8,
            0x6074f3b126a91b8aad66cf3f0c715d,
            0xaafd942e549933daeb8f6abf1baf63,
            0x56,
        ],
    };

    assert(verify_sha384_pss(sha384_hash, signature, 65537, 64));
}
