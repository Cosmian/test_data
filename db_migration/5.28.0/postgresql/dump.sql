--
-- PostgreSQL database dump
--


-- Dumped from database version 18.6 (Debian 18.6-1.pgdg13+2)
-- Dumped by pg_dump version 18.6 (Debian 18.6-1.pgdg13+2)

SET statement_timeout = 0;
SET lock_timeout = 0;
SET idle_in_transaction_session_timeout = 0;
SET transaction_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SELECT pg_catalog.set_config('search_path', '', false);
SET check_function_bodies = false;
SET xmloption = content;
SET client_min_messages = warning;
SET row_security = off;

SET default_tablespace = '';

SET default_table_access_method = heap;

--
-- Name: crls; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.crls (
    issuer_id character varying(128) NOT NULL,
    crl_der bytea NOT NULL,
    crl_number bigint NOT NULL,
    generated_at character varying(32) NOT NULL,
    next_update character varying(32) NOT NULL
);


--
-- Name: crypto_officer_activations; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.crypto_officer_activations (
    activated_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    activated_by character varying(255),
    sealed_record text NOT NULL,
    revoked_at timestamp without time zone,
    revoked_by character varying(255)
);


--
-- Name: objects; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.objects (
    id character varying(128) NOT NULL,
    object character varying NOT NULL,
    attributes jsonb NOT NULL,
    state character varying(32),
    owner character varying(255),
    wrapping_key_id character varying(128)
);


--
-- Name: parameters; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.parameters (
    name character varying(128) NOT NULL,
    value character varying(256)
);


--
-- Name: read_access; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.read_access (
    id character varying(128),
    userid character varying(255),
    permissions json NOT NULL
);


--
-- Name: tags; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.tags (
    id character varying(128),
    tag character varying(255)
);


--
-- Data for Name: crls; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: crypto_officer_activations; Type: TABLE DATA; Schema: public; Owner: -
--



--
-- Data for Name: objects; Type: TABLE DATA; Schema: public; Owner: -
--

INSERT INTO public.objects VALUES ('mig_kek', '{"SymmetricKey":{"KeyBlock":{"KeyFormatType":"TransparentSymmetricKey","KeyValue":{"KeyMaterial":{"Key":[146,50,154,162,225,153,81,155,94,166,10,85,201,109,220,35,251,170,112,124,195,158,7,139,13,147,99,164,207,215,147,151]},"Attributes":{"ActivationDate":"2026-11-02 20:49:51.0 +00:00:00","AlwaysSensitive":false,"CryptographicAlgorithm":"AES","CryptographicLength":256,"CryptographicUsageMask":2108,"Digest":{"HashingAlgorithm":"SHA256","DigestValue":[203,202,99,145,69,56,99,54,134,38,6,40,37,250,160,23,39,188,47,165,113,228,120,218,165,103,101,39,130,35,7,93],"KeyFormatType":"Raw"},"InitialDate":"2026-11-02 20:49:51.0 +00:00:00","KeyFormatType":"TransparentSymmetricKey","LastChangeDate":"2026-11-02 20:49:51.0 +00:00:00","ObjectType":"SymmetricKey","OriginalCreationDate":"2026-11-02 20:49:51.0 +00:00:00","State":"Active","UniqueIdentifier":"mig_kek","Attribute":[{"VendorIdentification":"cosmian","AttributeName":"tag","AttributeValue":{"_t":"TextString","_c":"[\"mig\",\"_kk\"]"}}]}},"CryptographicAlgorithm":"AES","CryptographicLength":256}}}', '{"State": "Active", "Digest": {"DigestValue": [203, 202, 99, 145, 69, 56, 99, 54, 134, 38, 6, 40, 37, 250, 160, 23, 39, 188, 47, 165, 113, 228, 120, 218, 165, 103, 101, 39, 130, 35, 7, 93], "KeyFormatType": "Raw", "HashingAlgorithm": "SHA256"}, "Attribute": [{"AttributeName": "tag", "AttributeValue": {"_c": "[\"mig\",\"_kk\"]", "_t": "TextString"}, "VendorIdentification": "cosmian"}], "ObjectType": "SymmetricKey", "InitialDate": "2026-11-02 20:49:51.0 +00:00:00", "KeyFormatType": "TransparentSymmetricKey", "ActivationDate": "2026-11-02 20:49:51.0 +00:00:00", "LastChangeDate": "2026-11-02 20:49:51.0 +00:00:00", "AlwaysSensitive": false, "UniqueIdentifier": "mig_kek", "CryptographicLength": 256, "OriginalCreationDate": "2026-11-02 20:49:51.0 +00:00:00", "CryptographicAlgorithm": "AES", "CryptographicUsageMask": 2108}', 'Active', 'admin', NULL);
INSERT INTO public.objects VALUES ('mig_wrapped', '{"SymmetricKey":{"KeyBlock":{"KeyFormatType":"TransparentSymmetricKey","KeyValue":[198,250,230,161,229,242,148,202,179,80,187,163,167,11,110,205,229,85,169,145,134,48,232,133,241,9,73,92,39,249,185,118,222,187,119,181,183,68,194,31],"CryptographicAlgorithm":"AES","CryptographicLength":256,"KeyWrappingData":{"WrappingMethod":"Encrypt","EncryptionKeyInformation":{"UniqueIdentifier":"mig_kek","CryptographicParameters":{"BlockCipherMode":"AESKeyWrapPadding"}},"EncodingOption":"NoEncoding"}}}}', '{"Link": [{"LinkType": "WrappingKeyLink", "LinkedObjectIdentifier": "mig_kek"}], "State": "Active", "Digest": {"DigestValue": [53, 190, 49, 113, 218, 181, 240, 46, 243, 2, 234, 189, 114, 44, 207, 13, 72, 36, 100, 22, 176, 247, 175, 62, 186, 55, 125, 22, 115, 27, 171, 48], "KeyFormatType": "Raw", "HashingAlgorithm": "SHA256"}, "Attribute": [{"AttributeName": "wrapping_key_id", "AttributeValue": {"_c": "mig_kek", "_t": "TextString"}, "VendorIdentification": "cosmian"}, {"AttributeName": "tag", "AttributeValue": {"_c": "[\"_kk\",\"mig\"]", "_t": "TextString"}, "VendorIdentification": "cosmian"}], "ObjectType": "SymmetricKey", "InitialDate": "2026-11-02 20:49:52.0 +00:00:00", "KeyFormatType": "TransparentSymmetricKey", "ActivationDate": "2026-11-02 20:49:52.0 +00:00:00", "LastChangeDate": "2026-11-02 20:49:52.0 +00:00:00", "AlwaysSensitive": false, "UniqueIdentifier": "mig_wrapped", "CryptographicLength": 256, "OriginalCreationDate": "2026-11-02 20:49:52.0 +00:00:00", "CryptographicAlgorithm": "AES", "CryptographicUsageMask": 2108}', 'Active', 'admin', 'mig_kek');
INSERT INTO public.objects VALUES ('mig_rsa', '{"PrivateKey":{"KeyBlock":{"KeyFormatType":"TransparentRSAPrivateKey","KeyValue":{"KeyMaterial":{"Modulus":[1,[4100303401,4293196844,2607412495,3005035516,2936524062,209844090,2654619060,4047296023,3951289907,1666681215,3269519404,2753601617,2621441229,394720776,2723201256,1203310293,1088508675,3257368109,145017135,701751295,1551560522,4249685555,4242865119,2707239725,3424882677,2275027435,3672253798,4203388820,3574082411,2232989967,2254914003,1999261311,3075740838,2129989334,2436653039,643361610,2382686765,3785596959,3802682657,2764769084,35181611,2843234698,1949168467,501194751,4052022178,1185121003,1982996473,3091497828,2133805980,5567632,1872712628,3479185416,981840978,2798677422,1786837784,2028688440,2870650434,3384562324,1026779934,2702393546,2937767726,3455743798,1499492215,3269870746]],"PrivateExponent":[1,[504250049,614387960,1530714622,3333552691,223983412,2481243030,2149622101,2083833467,1141016202,594495839,2667985580,2906803609,3286316925,4154812707,1668633407,4096513881,4155921096,2503564549,1073268774,3346833744,3663143191,1201026019,2184872765,4215606142,206003650,1757683244,2425038889,1375573847,2264638053,2415803663,999561788,97450504,1631814329,328611293,2213002414,2011149903,52190218,1936981498,3193951416,4240917342,1459344725,1514314476,3109990026,3330024233,2157258999,3775346942,3970460243,2181127954,2151780092,2781341441,2805846797,2006252690,8931813,492986736,2755883886,3328994112,1550628383,4218960314,388506579,2625713598,325830522,1560173471,3480557265,829429654]],"PublicExponent":[1,[65537]],"P":[1,[1305643167,2354091590,1409437708,17536999,2353753230,2740481485,1409003201,1900076687,1245261795,1571433504,3683592006,2306949957,689152379,3289453844,1270948688,2274289977,2725564825,2618077920,3593769234,1304819301,963164988,1433029579,3752564012,1066640558,3501672162,3249723368,3840365725,4094854610,2887766794,3308773374,2545074697,3756542253]],"Q":[1,[3752046647,2274724670,48738286,2390493542,954868414,2055154342,920049196,737801299,1940821399,2121967692,933568882,2294443548,4159093517,2370276239,510089664,4276855285,4056077239,1842225610,3667233702,2843341128,2896325001,153620634,3344392300,3717802221,257162250,4288207995,3993872209,1339639807,807444433,1418211663,843433913,3738541182]],"PrimeExponentP":[1,[3923200369,2121004497,978222160,2768671839,432678899,3493324986,4025976269,3364551157,1597743136,3957669018,1406745694,1223143282,2425501553,712416415,3046785927,1795588818,1274198703,49502530,924318483,3679640831,4259416709,432889319,3329556438,3558606854,4291526881,3219250541,260499244,1843717960,3255424318,3649908985,3061192195,143527805]],"PrimeExponentQ":[1,[3068364873,1589966459,3518625546,2729755593,734705968,2999079682,3758367814,1202928720,1558774436,3382797649,3060147656,1952366400,1295107242,539219152,1223023793,2394415105,1635483786,2244116502,3799070450,554480623,2251490912,80189367,976686818,807741058,3045051801,1349567572,3772622468,723351822,3309602391,2515990042,1527176435,1265708710]],"CRTCoefficient":[1,[641930507,1251811639,512237548,1660675520,2134669768,2602504323,764437140,4183365717,835549853,3294480466,998578188,2148518116,1517755521,2497884986,3194583534,2448268376,417958522,3559137164,2035815226,3229435350,2814810834,3581691724,319380454,2395814763,2746697784,127959465,1687004944,3273678451,1381864806,44483640,2871828240,2850853282]]},"Attributes":{"ActivationDate":"2026-11-02 20:49:52.0 +00:00:00","AlwaysSensitive":false,"CryptographicAlgorithm":"RSA","CryptographicLength":2048,"CryptographicParameters":{"CryptographicAlgorithm":"RSA"},"CryptographicUsageMask":2097152,"Digest":{"HashingAlgorithm":"SHA256","DigestValue":[148,52,186,110,37,170,255,126,240,81,108,79,190,19,48,124,235,27,246,70,10,160,21,221,50,227,173,158,102,98,129,56],"KeyFormatType":"PKCS1"},"InitialDate":"2026-11-02 20:49:52.0 +00:00:00","KeyFormatType":"TransparentRSAPrivateKey","LastChangeDate":"2026-11-02 20:49:52.0 +00:00:00","Link":[{"LinkType":"PublicKeyLink","LinkedObjectIdentifier":"mig_rsa_pk"}],"ObjectType":"PrivateKey","OriginalCreationDate":"2026-11-02 20:49:52.0 +00:00:00","State":"Active","UniqueIdentifier":"mig_rsa","Attribute":[{"VendorIdentification":"cosmian","AttributeName":"tag","AttributeValue":{"_t":"TextString","_c":"[\"mig\",\"_sk\"]"}}]}},"CryptographicAlgorithm":"RSA","CryptographicLength":2048}}}', '{"Link": [{"LinkType": "PublicKeyLink", "LinkedObjectIdentifier": "mig_rsa_pk"}], "State": "Active", "Digest": {"DigestValue": [148, 52, 186, 110, 37, 170, 255, 126, 240, 81, 108, 79, 190, 19, 48, 124, 235, 27, 246, 70, 10, 160, 21, 221, 50, 227, 173, 158, 102, 98, 129, 56], "KeyFormatType": "PKCS1", "HashingAlgorithm": "SHA256"}, "Attribute": [{"AttributeName": "tag", "AttributeValue": {"_c": "[\"mig\",\"_sk\"]", "_t": "TextString"}, "VendorIdentification": "cosmian"}], "ObjectType": "PrivateKey", "InitialDate": "2026-11-02 20:49:52.0 +00:00:00", "KeyFormatType": "TransparentRSAPrivateKey", "ActivationDate": "2026-11-02 20:49:52.0 +00:00:00", "LastChangeDate": "2026-11-02 20:49:52.0 +00:00:00", "AlwaysSensitive": false, "UniqueIdentifier": "mig_rsa", "CryptographicLength": 2048, "OriginalCreationDate": "2026-11-02 20:49:52.0 +00:00:00", "CryptographicAlgorithm": "RSA", "CryptographicUsageMask": 2097152, "CryptographicParameters": {"CryptographicAlgorithm": "RSA"}}', 'Active', 'admin', NULL);
INSERT INTO public.objects VALUES ('mig_rsa_pk', '{"PublicKey":{"KeyBlock":{"KeyFormatType":"TransparentRSAPublicKey","KeyValue":{"KeyMaterial":{"Modulus":[1,[4100303401,4293196844,2607412495,3005035516,2936524062,209844090,2654619060,4047296023,3951289907,1666681215,3269519404,2753601617,2621441229,394720776,2723201256,1203310293,1088508675,3257368109,145017135,701751295,1551560522,4249685555,4242865119,2707239725,3424882677,2275027435,3672253798,4203388820,3574082411,2232989967,2254914003,1999261311,3075740838,2129989334,2436653039,643361610,2382686765,3785596959,3802682657,2764769084,35181611,2843234698,1949168467,501194751,4052022178,1185121003,1982996473,3091497828,2133805980,5567632,1872712628,3479185416,981840978,2798677422,1786837784,2028688440,2870650434,3384562324,1026779934,2702393546,2937767726,3455743798,1499492215,3269870746]],"PublicExponent":[1,[65537]]},"Attributes":{"ActivationDate":"2026-11-02 20:49:52.0 +00:00:00","AlwaysSensitive":false,"CryptographicAlgorithm":"RSA","CryptographicLength":2048,"CryptographicParameters":{"CryptographicAlgorithm":"RSA"},"CryptographicUsageMask":2097152,"Digest":{"HashingAlgorithm":"SHA256","DigestValue":[1,76,75,76,58,12,47,184,79,105,230,24,18,254,228,48,48,21,73,145,60,73,197,10,76,118,16,215,240,193,136,92],"KeyFormatType":"PKCS1"},"InitialDate":"2026-11-02 20:49:52.0 +00:00:00","KeyFormatType":"TransparentRSAPublicKey","LastChangeDate":"2026-11-02 20:49:52.0 +00:00:00","Link":[{"LinkType":"PrivateKeyLink","LinkedObjectIdentifier":"mig_rsa"}],"ObjectType":"PublicKey","OriginalCreationDate":"2026-11-02 20:49:52.0 +00:00:00","State":"Active","UniqueIdentifier":"mig_rsa_pk","Attribute":[{"VendorIdentification":"cosmian","AttributeName":"tag","AttributeValue":{"_t":"TextString","_c":"[\"_pk\",\"mig\"]"}}]}},"CryptographicAlgorithm":"RSA","CryptographicLength":2048}}}', '{"Link": [{"LinkType": "PrivateKeyLink", "LinkedObjectIdentifier": "mig_rsa"}], "State": "Active", "Digest": {"DigestValue": [1, 76, 75, 76, 58, 12, 47, 184, 79, 105, 230, 24, 18, 254, 228, 48, 48, 21, 73, 145, 60, 73, 197, 10, 76, 118, 16, 215, 240, 193, 136, 92], "KeyFormatType": "PKCS1", "HashingAlgorithm": "SHA256"}, "Attribute": [{"AttributeName": "tag", "AttributeValue": {"_c": "[\"_pk\",\"mig\"]", "_t": "TextString"}, "VendorIdentification": "cosmian"}], "ObjectType": "PublicKey", "InitialDate": "2026-11-02 20:49:52.0 +00:00:00", "KeyFormatType": "TransparentRSAPublicKey", "ActivationDate": "2026-11-02 20:49:52.0 +00:00:00", "LastChangeDate": "2026-11-02 20:49:52.0 +00:00:00", "AlwaysSensitive": false, "UniqueIdentifier": "mig_rsa_pk", "CryptographicLength": 2048, "OriginalCreationDate": "2026-11-02 20:49:52.0 +00:00:00", "CryptographicAlgorithm": "RSA", "CryptographicUsageMask": 2097152, "CryptographicParameters": {"CryptographicAlgorithm": "RSA"}}', 'Active', 'admin', NULL);
INSERT INTO public.objects VALUES ('mig_revoked', '{"SymmetricKey":{"KeyBlock":{"KeyFormatType":"TransparentSymmetricKey","KeyValue":{"KeyMaterial":{"Key":[225,90,212,99,23,61,140,29,32,177,112,237,181,81,210,85,199,194,85,113,0,33,23,241,47,11,78,211,3,6,39,169]},"Attributes":{"ActivationDate":"2026-11-02 20:49:52.0 +00:00:00","AlwaysSensitive":false,"CryptographicAlgorithm":"AES","CryptographicLength":256,"CryptographicUsageMask":2108,"DeactivationDate":"2026-11-02 20:49:53.0 +00:00:00","Digest":{"HashingAlgorithm":"SHA256","DigestValue":[146,36,36,206,164,196,88,207,85,83,78,14,75,244,181,29,144,5,166,49,8,51,59,46,147,84,60,215,82,62,13,16],"KeyFormatType":"Raw"},"InitialDate":"2026-11-02 20:49:52.0 +00:00:00","KeyFormatType":"TransparentSymmetricKey","LastChangeDate":"2026-11-02 20:49:52.0 +00:00:00","ObjectType":"SymmetricKey","OriginalCreationDate":"2026-11-02 20:49:52.0 +00:00:00","RevocationReason":{"RevocationReasonCode":"Unspecified","RevocationMessage":"Migration fixture revocation"},"State":"Deactivated","UniqueIdentifier":"mig_revoked","Attribute":[{"VendorIdentification":"cosmian","AttributeName":"tag","AttributeValue":{"_t":"TextString","_c":"[\"_kk\",\"mig\"]"}}]}},"CryptographicAlgorithm":"AES","CryptographicLength":256}}}', '{"State": "Deactivated", "Digest": {"DigestValue": [146, 36, 36, 206, 164, 196, 88, 207, 85, 83, 78, 14, 75, 244, 181, 29, 144, 5, 166, 49, 8, 51, 59, 46, 147, 84, 60, 215, 82, 62, 13, 16], "KeyFormatType": "Raw", "HashingAlgorithm": "SHA256"}, "Attribute": [{"AttributeName": "tag", "AttributeValue": {"_c": "[\"_kk\",\"mig\"]", "_t": "TextString"}, "VendorIdentification": "cosmian"}], "ObjectType": "SymmetricKey", "InitialDate": "2026-11-02 20:49:52.0 +00:00:00", "KeyFormatType": "TransparentSymmetricKey", "ActivationDate": "2026-11-02 20:49:52.0 +00:00:00", "LastChangeDate": "2026-11-02 20:49:52.0 +00:00:00", "AlwaysSensitive": false, "DeactivationDate": "2026-11-02 20:49:53.0 +00:00:00", "RevocationReason": {"RevocationMessage": "Migration fixture revocation", "RevocationReasonCode": "Unspecified"}, "UniqueIdentifier": "mig_revoked", "CryptographicLength": 256, "OriginalCreationDate": "2026-11-02 20:49:52.0 +00:00:00", "CryptographicAlgorithm": "AES", "CryptographicUsageMask": 2108}', 'Deactivated', 'admin', NULL);
INSERT INTO public.objects VALUES ('d52128bd-8e32-4acc-9a2c-f85203347a51', '{"PrivateKey":{"KeyBlock":{"KeyFormatType":"TransparentRSAPrivateKey","KeyValue":{"KeyMaterial":{"Modulus":[1,[1236606439,816319515,1530753417,901601388,1510510141,2880324653,3153433326,3039015551,1633518279,1477108881,471036112,2057103927,3617427084,1848852227,2166415400,2490924462,3308283544,1292945959,2292579918,3332743146,1497453169,1478869350,2949843806,2509726562,1425451803,4280645173,668721768,3410463932,3373714865,3613151740,2369820359,2218808951,1230804230,4137937526,3125141284,3581095484,270485363,3453973938,460734160,1258319952,2444344783,2669138186,2476875611,2957788475,1402632704,3813105973,1107678270,254175821,1234110690,2510775585,4103220669,1189507133,2122613753,1271792231,2918001538,3226419088,3757776559,1693309904,4164993860,4284073670,3128040058,2159845694,4006520588,2930853696]],"PrivateExponent":[1,[362369729,2597938828,2687150112,2762960987,1519423490,1469505563,4120749709,2339409327,3706226461,2816303426,305927926,2813955627,2722276683,4086963473,1847248160,3993090912,2411717211,1271970719,2068826225,50054770,2457190929,1723726146,997511457,636392889,1484352971,3107545995,1810999289,552552579,2321979177,3517566934,1421402094,3194512252,4141341886,3795005870,3694310273,3561574000,510467984,2572170946,817982874,640947484,2580408235,3987425579,855065666,4267457472,1375811939,1737803363,4204038248,2109844692,1157064447,253384407,1522227648,2141454496,3277143588,12221027,249743848,3605852071,2094742541,1855118328,1772207441,3170737255,1672640288,2699944059,1678772688,417004650]],"PublicExponent":[1,[65537]],"P":[1,[1622293367,1557778186,45269705,3748645102,3012664495,1433985873,3043093085,1462777937,3819524106,2292925159,4264624002,1026757405,1593647543,3921908982,3351086477,247045670,3354916213,1565065844,3028201020,2023545524,636147137,3561671177,2588104433,3193325003,4068000847,354022971,3408189188,3147606587,2932715315,3960416795,510720206,3666973212]],"Q":[1,[3124686097,4090261873,4182336390,1360678262,3138917704,72414040,4230151037,1776708143,1612098183,4090815076,2112340235,2012101126,1647184798,504292817,514707429,4036393547,824161861,995445554,1145358705,1343226875,354183834,2143055858,1709133362,2988142740,1117455240,2055448454,2338028143,768409460,2215027501,3566646706,251348212,3432782311]],"PrimeExponentP":[1,[2509353079,1239338963,3971507398,624252751,655525402,586147759,4294738825,2246370606,2087835927,2196667488,2000270869,253590395,1140350667,2220183556,3765246180,3205953121,2489904983,1389457377,120153629,249079348,2602044519,3435089917,358743842,2660850465,3303688842,3887524038,1660263870,1915805717,3944680887,3953775029,3661319706,2857673113]],"PrimeExponentQ":[1,[4144720065,3100548097,1811698409,2343538769,4081875074,4019711143,994808885,3142049587,806049591,334394631,2179159502,1422591297,1715958187,3469906863,50843871,1205155469,618707192,2182833845,1415296410,245187073,4160774634,2503983451,3673597628,3841105402,3865925765,2182981909,2652507495,1024383429,336432976,3255019034,4227882759,3336142498]],"CRTCoefficient":[1,[265021291,2056321277,62712401,1184449347,4099384813,1304579762,1158018755,3454101650,434611275,1855438119,1585398099,3679910967,590865448,294023348,956154242,1156925876,3046582137,2182575819,2202387743,3999826078,1898533106,1993502875,813236996,2096775,750790916,137418389,191726587,3982385147,3227000494,1570990750,3852715305,2250846227]]},"Attributes":{"ActivationDate":"2026-11-02 20:49:53.996252411 +00:00:00","CertificateAttributes":{"CertificateSubjectCn":"Migration fixture","CertificateSubjectO":"","CertificateSubjectOu":"","CertificateSubjectEmail":"","CertificateSubjectC":"","CertificateSubjectSt":"","CertificateSubjectL":"","CertificateSubjectUid":"","CertificateSubjectSerialNumber":"","CertificateSubjectTitle":"","CertificateSubjectDc":"","CertificateSubjectDnQualifier":"","CertificateIssuerCn":"","CertificateIssuerO":"","CertificateIssuerOu":"","CertificateIssuerEmail":"","CertificateIssuerC":"","CertificateIssuerSt":"","CertificateIssuerL":"","CertificateIssuerUid":"","CertificateIssuerSerialNumber":"","CertificateIssuerTitle":"","CertificateIssuerDc":"","CertificateIssuerDnQualifier":""},"CryptographicAlgorithm":"RSA","CryptographicLength":2048,"CryptographicParameters":{"CryptographicAlgorithm":"RSA"},"Digest":{"HashingAlgorithm":"SHA256","DigestValue":[61,177,45,73,165,176,186,170,129,208,59,238,37,1,1,42,223,179,103,143,169,235,221,203,5,57,190,44,150,205,62,143],"KeyFormatType":"PKCS1"},"InitialDate":"2026-11-02 20:49:53.0 +00:00:00","KeyFormatType":"TransparentRSAPrivateKey","LastChangeDate":"2026-11-02 20:49:53.0 +00:00:00","Link":[{"LinkType":"PublicKeyLink","LinkedObjectIdentifier":"ac0bde5e-c6c8-48ea-b8a4-b91112d93e06"},{"LinkType":"CertificateLink","LinkedObjectIdentifier":"mig_cert"}],"ObjectType":"PrivateKey","OriginalCreationDate":"2026-11-02 20:49:53.0 +00:00:00","State":"PreActive","UniqueIdentifier":"d52128bd-8e32-4acc-9a2c-f85203347a51","Attribute":[{"VendorIdentification":"cosmian","AttributeName":"requested_validity_days","AttributeValue":{"_t":"Integer","_c":365}},{"VendorIdentification":"cosmian","AttributeName":"tag","AttributeValue":{"_t":"TextString","_c":"[\"_sk\",\"mig\"]"}}]}},"CryptographicAlgorithm":"RSA","CryptographicLength":2048}}}', '{"Link": [{"LinkType": "PublicKeyLink", "LinkedObjectIdentifier": "ac0bde5e-c6c8-48ea-b8a4-b91112d93e06"}, {"LinkType": "CertificateLink", "LinkedObjectIdentifier": "mig_cert"}], "State": "PreActive", "Digest": {"DigestValue": [61, 177, 45, 73, 165, 176, 186, 170, 129, 208, 59, 238, 37, 1, 1, 42, 223, 179, 103, 143, 169, 235, 221, 203, 5, 57, 190, 44, 150, 205, 62, 143], "KeyFormatType": "PKCS1", "HashingAlgorithm": "SHA256"}, "Attribute": [{"AttributeName": "requested_validity_days", "AttributeValue": {"_c": 365, "_t": "Integer"}, "VendorIdentification": "cosmian"}, {"AttributeName": "tag", "AttributeValue": {"_c": "[\"_sk\",\"mig\"]", "_t": "TextString"}, "VendorIdentification": "cosmian"}], "ObjectType": "PrivateKey", "InitialDate": "2026-11-02 20:49:53.0 +00:00:00", "KeyFormatType": "TransparentRSAPrivateKey", "ActivationDate": "2026-11-02 20:49:53.996252411 +00:00:00", "LastChangeDate": "2026-11-02 20:49:53.0 +00:00:00", "UniqueIdentifier": "d52128bd-8e32-4acc-9a2c-f85203347a51", "CryptographicLength": 2048, "OriginalCreationDate": "2026-11-02 20:49:53.0 +00:00:00", "CertificateAttributes": {"CertificateIssuerC": "", "CertificateIssuerL": "", "CertificateIssuerO": "", "CertificateIssuerCn": "", "CertificateIssuerDc": "", "CertificateIssuerOu": "", "CertificateIssuerSt": "", "CertificateSubjectC": "", "CertificateSubjectL": "", "CertificateSubjectO": "", "CertificateIssuerUid": "", "CertificateSubjectCn": "Migration fixture", "CertificateSubjectDc": "", "CertificateSubjectOu": "", "CertificateSubjectSt": "", "CertificateSubjectUid": "", "CertificateIssuerEmail": "", "CertificateIssuerTitle": "", "CertificateSubjectEmail": "", "CertificateSubjectTitle": "", "CertificateIssuerDnQualifier": "", "CertificateIssuerSerialNumber": "", "CertificateSubjectDnQualifier": "", "CertificateSubjectSerialNumber": ""}, "CryptographicAlgorithm": "RSA", "CryptographicParameters": {"CryptographicAlgorithm": "RSA"}}', 'Active', 'admin', NULL);
INSERT INTO public.objects VALUES ('ac0bde5e-c6c8-48ea-b8a4-b91112d93e06', '{"PublicKey":{"KeyBlock":{"KeyFormatType":"TransparentRSAPublicKey","KeyValue":{"KeyMaterial":{"Modulus":[1,[1236606439,816319515,1530753417,901601388,1510510141,2880324653,3153433326,3039015551,1633518279,1477108881,471036112,2057103927,3617427084,1848852227,2166415400,2490924462,3308283544,1292945959,2292579918,3332743146,1497453169,1478869350,2949843806,2509726562,1425451803,4280645173,668721768,3410463932,3373714865,3613151740,2369820359,2218808951,1230804230,4137937526,3125141284,3581095484,270485363,3453973938,460734160,1258319952,2444344783,2669138186,2476875611,2957788475,1402632704,3813105973,1107678270,254175821,1234110690,2510775585,4103220669,1189507133,2122613753,1271792231,2918001538,3226419088,3757776559,1693309904,4164993860,4284073670,3128040058,2159845694,4006520588,2930853696]],"PublicExponent":[1,[65537]]},"Attributes":{"ActivationDate":"2026-11-02 20:49:53.996252411 +00:00:00","CertificateAttributes":{"CertificateSubjectCn":"Migration fixture","CertificateSubjectO":"","CertificateSubjectOu":"","CertificateSubjectEmail":"","CertificateSubjectC":"","CertificateSubjectSt":"","CertificateSubjectL":"","CertificateSubjectUid":"","CertificateSubjectSerialNumber":"","CertificateSubjectTitle":"","CertificateSubjectDc":"","CertificateSubjectDnQualifier":"","CertificateIssuerCn":"","CertificateIssuerO":"","CertificateIssuerOu":"","CertificateIssuerEmail":"","CertificateIssuerC":"","CertificateIssuerSt":"","CertificateIssuerL":"","CertificateIssuerUid":"","CertificateIssuerSerialNumber":"","CertificateIssuerTitle":"","CertificateIssuerDc":"","CertificateIssuerDnQualifier":""},"CryptographicAlgorithm":"RSA","CryptographicLength":2048,"CryptographicParameters":{"CryptographicAlgorithm":"RSA"},"Digest":{"HashingAlgorithm":"SHA256","DigestValue":[150,114,40,39,73,28,228,86,176,113,61,87,17,110,236,82,201,71,38,167,77,2,138,59,20,33,136,79,0,116,16,200],"KeyFormatType":"PKCS1"},"InitialDate":"2026-11-02 20:49:53.0 +00:00:00","KeyFormatType":"TransparentRSAPublicKey","LastChangeDate":"2026-11-02 20:49:53.0 +00:00:00","Link":[{"LinkType":"PrivateKeyLink","LinkedObjectIdentifier":"d52128bd-8e32-4acc-9a2c-f85203347a51"},{"LinkType":"CertificateLink","LinkedObjectIdentifier":"mig_cert"}],"ObjectType":"PublicKey","OriginalCreationDate":"2026-11-02 20:49:53.0 +00:00:00","State":"PreActive","UniqueIdentifier":"ac0bde5e-c6c8-48ea-b8a4-b91112d93e06","Attribute":[{"VendorIdentification":"cosmian","AttributeName":"requested_validity_days","AttributeValue":{"_t":"Integer","_c":365}},{"VendorIdentification":"cosmian","AttributeName":"tag","AttributeValue":{"_t":"TextString","_c":"[\"_pk\",\"mig\"]"}}]}},"CryptographicAlgorithm":"RSA","CryptographicLength":2048}}}', '{"Link": [{"LinkType": "PrivateKeyLink", "LinkedObjectIdentifier": "d52128bd-8e32-4acc-9a2c-f85203347a51"}, {"LinkType": "CertificateLink", "LinkedObjectIdentifier": "mig_cert"}], "State": "PreActive", "Digest": {"DigestValue": [150, 114, 40, 39, 73, 28, 228, 86, 176, 113, 61, 87, 17, 110, 236, 82, 201, 71, 38, 167, 77, 2, 138, 59, 20, 33, 136, 79, 0, 116, 16, 200], "KeyFormatType": "PKCS1", "HashingAlgorithm": "SHA256"}, "Attribute": [{"AttributeName": "requested_validity_days", "AttributeValue": {"_c": 365, "_t": "Integer"}, "VendorIdentification": "cosmian"}, {"AttributeName": "tag", "AttributeValue": {"_c": "[\"_pk\",\"mig\"]", "_t": "TextString"}, "VendorIdentification": "cosmian"}], "ObjectType": "PublicKey", "InitialDate": "2026-11-02 20:49:53.0 +00:00:00", "KeyFormatType": "TransparentRSAPublicKey", "ActivationDate": "2026-11-02 20:49:53.996252411 +00:00:00", "LastChangeDate": "2026-11-02 20:49:53.0 +00:00:00", "UniqueIdentifier": "ac0bde5e-c6c8-48ea-b8a4-b91112d93e06", "CryptographicLength": 2048, "OriginalCreationDate": "2026-11-02 20:49:53.0 +00:00:00", "CertificateAttributes": {"CertificateIssuerC": "", "CertificateIssuerL": "", "CertificateIssuerO": "", "CertificateIssuerCn": "", "CertificateIssuerDc": "", "CertificateIssuerOu": "", "CertificateIssuerSt": "", "CertificateSubjectC": "", "CertificateSubjectL": "", "CertificateSubjectO": "", "CertificateIssuerUid": "", "CertificateSubjectCn": "Migration fixture", "CertificateSubjectDc": "", "CertificateSubjectOu": "", "CertificateSubjectSt": "", "CertificateSubjectUid": "", "CertificateIssuerEmail": "", "CertificateIssuerTitle": "", "CertificateSubjectEmail": "", "CertificateSubjectTitle": "", "CertificateIssuerDnQualifier": "", "CertificateIssuerSerialNumber": "", "CertificateSubjectDnQualifier": "", "CertificateSubjectSerialNumber": ""}, "CryptographicAlgorithm": "RSA", "CryptographicParameters": {"CryptographicAlgorithm": "RSA"}}', 'Active', 'admin', NULL);
INSERT INTO public.objects VALUES ('mig_cert', '{"Certificate":{"CertificateType":"X509","CertificateValue":[48,130,2,211,48,130,1,187,160,3,2,1,2,2,20,95,106,15,56,53,207,240,187,25,177,136,250,99,220,193,137,155,20,78,140,48,13,6,9,42,134,72,134,247,13,1,1,11,5,0,48,28,49,26,48,24,6,3,85,4,3,12,17,77,105,103,114,97,116,105,111,110,32,102,105,120,116,117,114,101,48,30,23,13,50,54,49,49,48,50,50,48,52,57,53,51,90,23,13,50,55,49,49,48,50,50,48,52,57,53,51,90,48,28,49,26,48,24,6,3,85,4,3,12,17,77,105,103,114,97,116,105,111,110,32,102,105,120,116,117,114,101,48,130,1,34,48,13,6,9,42,134,72,134,247,13,1,1,1,5,0,3,130,1,15,0,48,130,1,10,2,130,1,1,0,174,177,71,64,238,206,167,12,128,188,161,62,186,114,26,122,255,89,198,198,248,64,195,68,100,237,219,208,223,251,30,175,192,79,63,144,173,237,43,130,75,206,2,103,126,132,131,249,70,230,112,61,244,146,45,189,149,167,101,33,73,143,8,226,15,38,106,77,66,5,212,62,227,71,97,53,83,154,122,0,176,76,69,59,147,162,31,91,159,23,209,10,145,177,189,207,75,0,112,80,27,118,62,208,205,223,117,178,16,31,71,115,213,115,46,60,186,69,223,36,246,163,234,118,73,92,149,6,132,64,86,119,141,64,150,199,215,92,81,252,201,22,205,177,203,71,140,188,39,219,226,104,255,37,118,53,84,246,171,27,149,151,99,98,175,211,11,94,88,37,193,102,89,65,82,113,198,165,159,234,136,165,254,78,77,16,202,39,197,48,102,152,148,120,125,174,129,32,224,40,110,51,63,3,215,157,142,140,122,156,234,55,28,19,112,208,88,10,228,145,97,93,130,199,181,35,178,127,187,245,146,238,171,174,68,45,90,8,142,61,53,189,88,108,91,61,113,137,48,168,12,27,73,181,29,231,2,3,1,0,1,163,13,48,11,48,9,6,3,85,29,56,4,2,5,0,48,13,6,9,42,134,72,134,247,13,1,1,11,5,0,3,130,1,1,0,131,237,163,177,191,180,43,124,249,146,73,160,104,190,85,16,1,200,225,80,111,81,166,189,90,66,199,144,203,143,24,91,193,90,65,21,45,210,93,111,168,254,65,251,251,65,175,14,167,216,250,69,150,87,245,160,175,140,183,245,123,203,99,162,142,194,3,126,30,13,15,93,170,151,19,144,86,220,173,211,165,137,63,211,104,23,86,249,24,32,75,9,6,98,123,107,144,250,13,141,191,108,226,215,7,224,225,95,171,110,8,207,182,109,107,249,235,13,71,110,75,148,202,221,152,98,131,29,5,143,101,38,23,122,138,130,186,245,35,219,146,94,180,68,26,88,185,61,117,215,50,71,193,120,143,77,29,203,191,77,228,38,111,53,127,50,15,241,144,106,234,135,71,247,205,49,44,18,244,234,91,187,127,238,58,95,143,93,27,27,173,108,93,46,42,85,247,58,13,237,53,190,135,201,51,182,127,255,14,25,218,32,120,176,140,203,107,164,46,204,221,187,3,92,139,182,170,170,136,240,148,184,145,11,82,174,8,156,172,249,9,172,231,38,222,208,36,168,57,89,190,7,195,112,239,87]}}', '{"Link": [{"LinkType": "CertificateLink", "LinkedObjectIdentifier": "mig_cert"}, {"LinkType": "PublicKeyLink", "LinkedObjectIdentifier": "ac0bde5e-c6c8-48ea-b8a4-b91112d93e06"}, {"LinkType": "PrivateKeyLink", "LinkedObjectIdentifier": "d52128bd-8e32-4acc-9a2c-f85203347a51"}], "ObjectType": "Certificate", "InitialDate": "2026-11-02 20:49:53.0 +00:00:00", "KeyFormatType": "X509", "ActivationDate": "2026-11-02 20:49:53.0 +00:00:00", "UniqueIdentifier": "mig_cert", "CertificateAttributes": {"CertificateIssuerC": "", "CertificateIssuerL": "", "CertificateIssuerO": "", "CertificateIssuerCn": "Migration fixture", "CertificateIssuerDc": "", "CertificateIssuerOu": "", "CertificateIssuerSt": "", "CertificateSubjectC": "", "CertificateSubjectL": "", "CertificateSubjectO": "", "CertificateIssuerUid": "", "CertificateSubjectCn": "Migration fixture", "CertificateSubjectDc": "", "CertificateSubjectOu": "", "CertificateSubjectSt": "", "CertificateSubjectUid": "f46f9cc8ce857a267527045954a4cab227fa6f1b", "CertificateIssuerEmail": "", "CertificateIssuerTitle": "", "CertificateSubjectEmail": "", "CertificateSubjectTitle": "", "CertificateIssuerDnQualifier": "", "CertificateIssuerSerialNumber": "", "CertificateSubjectDnQualifier": "", "CertificateSubjectSerialNumber": "5F6A0F3835CFF0BB19B188FA63DCC1899B144E8C"}}', 'Active', 'admin', NULL);


--
-- Data for Name: parameters; Type: TABLE DATA; Schema: public; Owner: -
--

INSERT INTO public.parameters VALUES ('wrapping_key_id_backfilled', 'true');


--
-- Data for Name: read_access; Type: TABLE DATA; Schema: public; Owner: -
--

INSERT INTO public.read_access VALUES ('mig_kek', 'mig_user', '["get","encrypt","decrypt"]');


--
-- Data for Name: tags; Type: TABLE DATA; Schema: public; Owner: -
--

INSERT INTO public.tags VALUES ('mig_kek', '_kk');
INSERT INTO public.tags VALUES ('mig_kek', 'mig');
INSERT INTO public.tags VALUES ('mig_wrapped', '_kk');
INSERT INTO public.tags VALUES ('mig_wrapped', 'mig');
INSERT INTO public.tags VALUES ('mig_rsa', 'mig');
INSERT INTO public.tags VALUES ('mig_rsa', '_sk');
INSERT INTO public.tags VALUES ('mig_rsa_pk', 'mig');
INSERT INTO public.tags VALUES ('mig_rsa_pk', '_pk');
INSERT INTO public.tags VALUES ('mig_revoked', '_kk');
INSERT INTO public.tags VALUES ('mig_revoked', 'mig');
INSERT INTO public.tags VALUES ('d52128bd-8e32-4acc-9a2c-f85203347a51', 'mig');
INSERT INTO public.tags VALUES ('d52128bd-8e32-4acc-9a2c-f85203347a51', '_sk');
INSERT INTO public.tags VALUES ('ac0bde5e-c6c8-48ea-b8a4-b91112d93e06', 'mig');
INSERT INTO public.tags VALUES ('ac0bde5e-c6c8-48ea-b8a4-b91112d93e06', '_pk');
INSERT INTO public.tags VALUES ('mig_cert', '_cert');
INSERT INTO public.tags VALUES ('mig_cert', 'mig');


--
-- Name: crls crls_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.crls
    ADD CONSTRAINT crls_pkey PRIMARY KEY (issuer_id);


--
-- Name: objects objects_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.objects
    ADD CONSTRAINT objects_pkey PRIMARY KEY (id);


--
-- Name: parameters parameters_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.parameters
    ADD CONSTRAINT parameters_pkey PRIMARY KEY (name);


--
-- Name: read_access read_access_id_userid_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.read_access
    ADD CONSTRAINT read_access_id_userid_key UNIQUE (id, userid);


--
-- Name: tags tags_id_tag_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.tags
    ADD CONSTRAINT tags_id_tag_key UNIQUE (id, tag);


--
-- Name: idx_co_activations_active; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX idx_co_activations_active ON public.crypto_officer_activations USING btree (activated_by) WHERE (revoked_at IS NULL);


--
-- Name: idx_objects_owner; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_objects_owner ON public.objects USING btree (owner);


--
-- Name: idx_objects_rotate_auto; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_objects_rotate_auto ON public.objects USING btree (state) WHERE ((attributes ->> 'RotateAutomatic'::text) = 'true'::text);


--
-- Name: idx_objects_rotate_name; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_objects_rotate_name ON public.objects USING btree (((attributes ->> 'RotateName'::text)), owner) WHERE ((attributes ->> 'RotateName'::text) IS NOT NULL);


--
-- Name: idx_objects_state; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_objects_state ON public.objects USING btree (state);


--
-- Name: idx_objects_type_state; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_objects_type_state ON public.objects USING btree (((attributes ->> 'ObjectType'::text)), state);


--
-- Name: idx_objects_wrapping_key_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_objects_wrapping_key_id ON public.objects USING btree (wrapping_key_id);


--
-- Name: idx_read_access_userid; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_read_access_userid ON public.read_access USING btree (userid);


--
-- Name: idx_tags_tag_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_tags_tag_id ON public.tags USING btree (tag, id);


--
-- PostgreSQL database dump complete
--


