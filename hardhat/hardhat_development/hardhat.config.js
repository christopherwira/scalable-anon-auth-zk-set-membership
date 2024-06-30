/** @type import('hardhat/config').HardhatUserConfig */
module.exports = {
  defaultNetwork: "hardhat",
  networks: {
    hardhat: {
      accounts: {
        mnemonic: "test test test test test test test test test test test junk",
        path: "m/44'/60'/0'/0",
        initialIndex: 0,
        count: 8,
        accountsBalance: "10000000000000000000000",
        passphrase: "",
      },
    },
  },
  solidity: "0.8.24",
};
