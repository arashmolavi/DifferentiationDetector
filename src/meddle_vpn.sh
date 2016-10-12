#echo $1
if [ $1 = "connect" ];
then
	scutil --nc start meddle
elif [  $1 = "disconnect" ];
then
	scutil --nc stop meddle
elif [  $1 = "status" ];
then
	scutil --nc status meddle
fi