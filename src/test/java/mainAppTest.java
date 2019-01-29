import org.junit.Test;
import org.web3j.abi.FunctionEncoder;
import org.web3j.abi.FunctionReturnDecoder;
import org.web3j.abi.TypeReference;
import org.web3j.abi.datatypes.Address;
import org.web3j.abi.datatypes.Function;
import org.web3j.abi.datatypes.Type;
import org.web3j.abi.datatypes.generated.Uint256;
import org.web3j.crypto.*;
import org.web3j.protocol.Web3j;
import org.web3j.protocol.core.DefaultBlockParameterName;
import org.web3j.protocol.core.Request;
import org.web3j.protocol.core.methods.request.Transaction;
import org.web3j.protocol.core.methods.response.*;
import org.web3j.protocol.http.HttpService;
import org.web3j.tx.ChainId;
import org.web3j.tx.Transfer;
import org.web3j.utils.Convert;
import org.web3j.utils.Numeric;

import java.io.IOException;
import java.math.BigDecimal;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;

import static org.web3j.crypto.Hash.sha256;

public class mainAppTest {

    //gas单价
    BigInteger gasPrice = new BigInteger("100000");

    /*chainId(即network_id)的分类:1为mainnet(即主网),2为Morden (disused),Expanse mainnet,
      3为Ropsten,4为Rinkeby,30为rootstock mainnet,31为rootstock testnet,
      42为Kovan,61为Ethereum Classic mainnet(即ETC主网),62为Ethereum Classic testnet(即ETC测试网),
      1337为geth private chains(default)*/
    byte chainId = 4;

    @Test
    public void test1() throws IOException {
        //设置监听哪个节点,可以是本地测试节点,本地全节点,也可以是infura上的节点,不过要注意infura上的节点不能设置过滤器
        Web3j web3j = Web3j.build(new HttpService(
                "https://rinkeby.infura.io/v3/e87cfbdec9f047c5a6d53d4b2e47a960"));

        //助记词
        String mnemonic = "enrich country host master payment expect ozone usage unhappy autumn screen post";
        //该助记词的密码
        String password = "admin";
        //私钥
        String privateKey = "f2add6b62dd3e4d4b81cc1201a06a4a3e44bed0f1d82551381989df47f411284";
        //地址
        String address = "0xa102866618809cf2845d22aafc0e3b7bc6169fe6";
        //合约地址
        String contractAddress = "0x741f10326092e5278019d5e25728a836b9b13408";

        //根据助记词生成凭证Credential
        Credentials credentials = createCredentialByMnemonic(mnemonic,password);

        /*//根据私钥生成凭证Credential
        Credentials credentials = createCredentialByPrivateKey(privateKey);*/

        /*//根据钱包文件(又叫keystore文件)生成凭证Credential
        Credentials credentials = createCredentialByWalletFile();*/

        //加载已部署的智能合约实例
        ZMToken contract = initContract(contractAddress,web3j,credentials);

        //获取指定地址的ETH余额
        BigDecimal balance = getBalance(web3j,address);

        //获取指定地址的nonce
        BigInteger nonce = getNonce(web3j,address);

        //获取指定地址在指定合约上的代币余额
        BigInteger tokenBalance = getTokenBalanceBaseFunction(web3j,address,contractAddress);

        //根据hash值获取交易详情
        EthTransaction ethTransaction = getTransactionByHash(web3j,"0xb7b48ee9ce399b93f447fe0ee95dd140b9fd68d545a8ba3b56c2e435a47dd582");

        System.out.println("balance值:"+balance);
        System.out.println("nonce值:"+nonce);
        System.out.println("tokenBalance值:"+tokenBalance);
        System.out.println("TX详情:"+ethTransaction.getTransaction());
    }

    //加载已部署的智能合约实例
    private ZMToken initContract(String contractAddress,Web3j web3j,Credentials credentials) {
        ZMToken contract = (ZMToken) ZMToken.load(
        contractAddress,web3j, credentials, gasPrice, new BigInteger("3000000"));
        return contract;
    }

    //根据助记词生成凭证Credential
    public Credentials createCredentialByMnemonic(String mnemonic,String password){
        byte[] seed = MnemonicUtils.generateSeed(mnemonic, password);
        Credentials credentials = Credentials.create(ECKeyPair.create(sha256(seed)));
        return credentials;
    }

    //根据私钥生成凭证Credential
    public Credentials createCredentialByPrivateKey(String privateKey){
        Credentials credentials = Credentials.create(privateKey);
        return credentials;
    }

    //根据钱包文件(又叫keystore文件)生成凭证Credential
    public Credentials createCredentialByWalletFile() throws IOException, CipherException {
        // 第一个变量填入账户的密码，第二个变量填入账户文件的 path
        Credentials credentials = WalletUtils.loadCredentials(
                "123",
                "/datadir/chain/keystore/UTC--2018-03-14T14-46-38.646997441Z--c2acba996f709d4b806d3330996f49d50f088258");
        return credentials;
    }

    //获取指定地址ETH余额
    public BigDecimal getBalance(Web3j web3j, String address) throws IOException {
        EthGetBalance ethGetBalance = web3j.ethGetBalance(address, DefaultBlockParameterName.LATEST).send();
        if(ethGetBalance!=null){
            // 打印账户余额
            System.out.println(ethGetBalance.getBalance());
            // 将单位转为以太，方便查看
            System.out.println(Convert.fromWei(ethGetBalance.getBalance().toString(), Convert.Unit.ETHER));
            return Convert.fromWei(ethGetBalance.getBalance().toString(), Convert.Unit.ETHER);
        }
        return new BigDecimal("0");
    }

    //获取账户的nonce
    public BigInteger getNonce(Web3j web3j, String addr) throws IOException {
        EthGetTransactionCount getNonce = web3j.ethGetTransactionCount(addr,DefaultBlockParameterName.PENDING).send();
        if (getNonce == null){
            throw new RuntimeException("net error");
        }
        return getNonce.getTransactionCount();
    }

    //估算手续费上限(即gaslimit)
    public BigInteger getTransactionGasLimit(Web3j web3j, Transaction transaction) {
        try {
            EthEstimateGas ethEstimateGas = web3j.ethEstimateGas(transaction).send();
            if (ethEstimateGas.hasError()){
                throw new RuntimeException(ethEstimateGas.getError().getMessage());
            }
            return ethEstimateGas.getAmountUsed();
        } catch (IOException e) {
            throw new RuntimeException("net error");
        }
    }

    //根据hash值获取交易信息
    public EthTransaction getTransactionByHash(Web3j web3j,String hash) throws IOException {
        Request<?, EthTransaction> request = web3j.ethGetTransactionByHash(hash);
        return request.send();
    }

    //推荐使用的ETH转账方法
    public TransactionReceipt transferETH(Web3j web3j,Credentials credentials,String toAddress,BigDecimal value) throws Exception {
        TransactionReceipt transactionReceipt = Transfer.sendFunds(
                web3j, credentials, toAddress,
                value, Convert.Unit.ETHER)
                .send();
        return  transactionReceipt;
    }

    //通过调整gasprice调整以太坊交易确认被打包的速度(仅限于主网)
    public void adjustMineSpeedByGasPrice(){
        //Get请求https://ethgasstation.info/json/ethgasAPI.json,可以得到下面的json

        /*{
            "average":25, //平均值(Gwei*10的结果)
                "fastestWait":0.5,
                "fastWait":0.7,
                "fast":36,  //最快(Gwei*10的结果)
                "safeLowWait":1.2,
                "blockNum":6274955,
                "avgWait":1.2,
                "block_time":13.876288659793815,
                "speed":0.9481897143119544,
                "fastest":330,
                "safeLow":25    //安全最低值(Gwei*10的结果)
        }*/

        /*//发送交易平均正常速度被打包gasprice,单位是wei
        String average_gasprice_wei = average*10e8;
        //发送交易超快被打包的gasprice,单位是wei
        String fast_gasprice_wei = fast*10e8;
        //发送交易最慢被打包的gasprice,单位是wei
        String safeLow_gasprice_wei = safeLow*10e8;*/
    }






    //ETH转账的底层原理实现(日常需求中不推荐使用此方法,仅供学习使用)
    public String transferETHBaseFunction(Web3j web3j, String fromAddr, String privateKey, String toAddr, BigDecimal amount, String data) throws IOException {
        // 获得nonce
        BigInteger nonce = getNonce(web3j, fromAddr);
        // value 转换
        BigInteger value = Convert.toWei(amount, Convert.Unit.ETHER).toBigInteger();
        // 构建交易
        Transaction transaction = createEthTransaction(fromAddr, nonce, gasPrice, null, toAddr, value);
        // 计算gasLimit
        BigInteger gasLimit = getTransactionGasLimit(web3j, transaction);
        // 查询调用者余额，检测余额是否充足
        BigDecimal ethBalance = getBalance(web3j, fromAddr);
        BigDecimal balance = Convert.toWei(ethBalance, Convert.Unit.ETHER);
        if (balance.compareTo(amount.add(new BigDecimal(gasLimit.toString()))) < 0) {
            throw new RuntimeException("余额不足，请核实");
        }

        return signAndSend(web3j, nonce, gasPrice, gasLimit, toAddr, value, data, chainId, privateKey);
    }

    //代币转账的底层原理实现(日常需求中不推荐使用此方法，仅供学习使用)
    public String transferTokenBaseFunction(Web3j web3j, String fromAddr, String privateKey, String toAddr, String contractAddr, long amount) throws IOException {

        BigInteger nonce = getNonce(web3j, fromAddr);
        // 要调用的合约方法名称,
        String method = "transfer";

        // 构建输入参数
        List<Type> inputArgs = new ArrayList<>();
        inputArgs.add(new Address(toAddr));
        inputArgs.add(new Uint256(BigDecimal.valueOf(amount).multiply(BigDecimal.TEN.pow(18)).toBigInteger()));

        // 合约返回值容器
        List<TypeReference<?>> outputArgs = new ArrayList<>();

        String funcABI = FunctionEncoder.encode(new Function(method, inputArgs, outputArgs));

        Transaction transaction = Transaction.createFunctionCallTransaction(fromAddr, nonce, gasPrice, null, contractAddr, funcABI);
        RawTransaction rawTransaction = RawTransaction.createTransaction(nonce, gasPrice, null, contractAddr, null, funcABI);

        BigInteger gasLimit = getTransactionGasLimit(web3j, transaction);

        // 获得余额
        BigDecimal ethBalance = getBalance(web3j, fromAddr);
        BigInteger tokenBalance = getTokenBalanceBaseFunction(web3j, fromAddr, contractAddr);
        BigInteger balance = Convert.toWei(ethBalance, Convert.Unit.ETHER).toBigInteger();

        if (balance.compareTo(gasLimit) < 0) {
            throw new RuntimeException("手续费不足，请核实");
        }
        if (tokenBalance.compareTo(BigDecimal.valueOf(amount).toBigInteger()) < 0) {
            throw new RuntimeException("代币不足，请核实");
        }

        return signAndSend(web3j, nonce, gasPrice, gasLimit, contractAddr, BigInteger.ZERO, funcABI, chainId, privateKey);
    }

    //对交易签名并发送交易
    public String signAndSend(Web3j web3j, BigInteger nonce, BigInteger gasPrice, BigInteger gasLimit, String to, BigInteger value, String data, byte chainId, String privateKey) {
        String txHash = "";
        RawTransaction rawTransaction = RawTransaction.createTransaction(nonce, gasPrice, gasLimit, to, value, data);
        if (privateKey.startsWith("0x")){
            privateKey = privateKey.substring(2);
        }

        ECKeyPair ecKeyPair = ECKeyPair.create(new BigInteger(privateKey, 16));
        Credentials credentials = Credentials.create(ecKeyPair);

        byte[] signMessage;
        if (chainId > ChainId.NONE){
            signMessage = TransactionEncoder.signMessage(rawTransaction, chainId, credentials);
        } else {
            signMessage = TransactionEncoder.signMessage(rawTransaction, credentials);
        }

        String signData = Numeric.toHexString(signMessage);
        if (!"".equals(signData)) {
            try {
                EthSendTransaction send = web3j.ethSendRawTransaction(signData).send();
                txHash = send.getTransactionHash();
            } catch (IOException e) {
                throw new RuntimeException("交易异常");
            }
        }
        return txHash;
    }

    //构造ETH交易
    public Transaction createEthTransaction(String fromAddr, BigInteger nonce, BigInteger gasPrice, BigInteger gasLimit, String toAddr,
                                            BigInteger value){
        Transaction transaction = Transaction.createEtherTransaction(fromAddr, nonce, gasPrice, gasLimit, toAddr, value);
        return transaction;
    }

    //构造合约调用交易
    public Transaction createContractTransaction(String fromAddr, BigInteger nonce, BigInteger gasPrice, BigInteger gasLimit, String contractAddr,
                                                 String data){
        Transaction transaction = Transaction.createFunctionCallTransaction(fromAddr, nonce, gasPrice, gasLimit, contractAddr, data);
        return transaction;
    }

    //获取指定地址在指定合约上的代币余额的底层实现(日常需求中不推荐使用此方法，仅供学习使用)
    public BigInteger getTokenBalanceBaseFunction(Web3j web3j, String fromAddress, String contractAddress) {
        String methodName = "balanceOf";
        List<Type> inputParameters = new ArrayList<>();
        List<TypeReference<?>> outputParameters = new ArrayList<>();
        Address address = new Address(fromAddress);
        inputParameters.add(address);

        TypeReference<Uint256> typeReference = new TypeReference<Uint256>() {
        };
        outputParameters.add(typeReference);
        Function function = new Function(methodName, inputParameters, outputParameters);
        String data = FunctionEncoder.encode(function);
        Transaction transaction = Transaction.createEthCallTransaction(fromAddress, contractAddress, data);

        EthCall ethCall;
        BigInteger balanceValue = BigInteger.ZERO;
        try {
            ethCall = web3j.ethCall(transaction, DefaultBlockParameterName.LATEST).send();
            List<Type> results = FunctionReturnDecoder.decode(ethCall.getValue(), function.getOutputParameters());
            balanceValue = (BigInteger) results.get(0).getValue();
        } catch (IOException e) {
            e.printStackTrace();
        }
        return balanceValue;
    }

}