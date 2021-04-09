coreInfo=`curl -s -X GET \
"https://api.supertokens.io/0/core/latest?password=$SUPERTOKENS_API_KEY&planType=FREE&mode=DEV&version=$1" \
-H 'api-version: 0'`
if [[ `echo $coreInfo | jq .tag` == "null" ]]
then
    echo "fetching latest X.Y.Z version for core, X.Y version: $1, planType: FREE gave response: $coreInfo"
    exit 1
fi
coreTag=$(echo $coreInfo | jq .tag | tr -d '"')
coreVersion=$(echo $coreInfo | jq .version | tr -d '"')

pluginInterfaceVersionXY=`curl -s -X GET \
"https://api.supertokens.io/0/core/dependency/plugin-interface/latest?password=$SUPERTOKENS_API_KEY&planType=FREE&mode=DEV&version=$1" \
-H 'api-version: 0'`
if [[ `echo $pluginInterfaceVersionXY | jq .pluginInterface` == "null" ]]
then
    echo "fetching latest X.Y version for plugin-interface, given core X.Y version: $1, planType: FREE gave response: $pluginInterfaceVersionXY"
    exit 1
fi
pluginInterfaceVersionXY=$(echo $pluginInterfaceVersionXY | jq .pluginInterface | tr -d '"')

pluginInterfaceInfo=`curl -s -X GET \
"https://api.supertokens.io/0/plugin-interface/latest?password=$SUPERTOKENS_API_KEY&planType=FREE&mode=DEV&version=$pluginInterfaceVersionXY" \
-H 'api-version: 0'`
if [[ `echo $pluginInterfaceInfo | jq .tag` == "null" ]]
then
    echo "fetching latest X.Y.Z version for plugin-interface, X.Y version: $pluginInterfaceVersionXY, planType: FREE gave response: $pluginInterfaceInfo"
    exit 1
fi
pluginInterfaceTag=$(echo $pluginInterfaceInfo | jq .tag | tr -d '"')
pluginInterfaceVersion=$(echo $pluginInterfaceInfo | jq .version | tr -d '"')

pluginVersionXY=`curl -s -X GET \
"https://api.supertokens.io/0/plugin-interface/dependency/plugin/latest?password=$SUPERTOKENS_API_KEY&planType=FREE&mode=DEV&version=$pluginInterfaceVersionXY&pluginName=mysql" \
-H 'api-version: 0'`
if [[ `echo $pluginVersionXY | jq .plugin` == "null" ]]
then
    echo "fetching latest X.Y version for mysql given plugin-interface X.Y version: $pluginInterfaceVersionXY gave response: $pluginVersionXY"
    exit 1
fi
pluginVersionXY=$(echo $pluginVersionXY | jq .plugin | tr -d '"')

pluginInfo=`curl -s -X GET \
"https://api.supertokens.io/0/plugin/latest?password=$SUPERTOKENS_API_KEY&planType=FREE&mode=DEV&version=$pluginVersionXY&name=mysql" \
-H 'api-version: 0'`
if [[ `echo $pluginInfo | jq .tag` == "null" ]]
then
    echo "fetching latest X.Y.Z version for mysql, X.Y version: $pluginVersionXY gave response: $pluginInfo"
    exit 1
fi
pluginTag=$(echo $pluginInfo | jq .tag | tr -d '"')
pluginVersion=$(echo $pluginInfo | jq .version | tr -d '"')

echo "Testing with frontend website: $2, FREE core: $coreVersion, plugin-interface: $pluginInterfaceVersion, mysql plugin: $pluginVersion"

(cd / && ./runMySQL.sh)
mysql -u root --password=root -e "DROP DATABASE IF EXISTS auth_session;"
mysql -u root --password=root -e "CREATE DATABASE auth_session;"
cd ../../
git clone git@github.com:supertokens/supertokens-root.git
cd supertokens-root
echo -e "core,$1\nplugin-interface,$pluginInterfaceVersionXY\nmysql-plugin,$pluginVersionXY" > modules.txt
./loadModules --ssh
cd supertokens-core
git checkout $coreTag
cd ../supertokens-plugin-interface
git checkout $pluginInterfaceTag
cd ../supertokens-mysql-plugin
git checkout $pluginTag
cd ../
echo $SUPERTOKENS_API_KEY > apiPassword
./utils/setupTestEnvLocal
cd ../
git clone git@github.com:supertokens/supertokens-website.git
cd supertokens-website
git checkout $2
cd ../project/tests/frontendIntegration/
SUPERTOKENS_ENV=testing uvicorn app:app --host 0.0.0.0 --port 8080 &
pid=$!
SUPERTOKENS_ENV=testing uvicorn app:app --host 0.0.0.0 --port 8082 &
pid2=$!
cd ../../../supertokens-website/test/server
npm i -d
npm i git+https://github.com:supertokens/supertokens-node.git#$3
cd ../../
npm i -d
NODE_PORT=8081 INSTALL_PATH=../supertokens-root npm test
if [[ $? -ne 0 ]]
then
    echo "test failed... exiting!"
    exit 1
fi
rm -rf ./test/server/node_modules/supertokens-node
git checkout HEAD -- ./test/server/package.json
kill -15 $pid
kill -15 $pid2